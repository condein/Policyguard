"""The Policy Gateway.

Every tool call proposed by the LLM flows through :meth:`PolicyGateway.evaluate`
and comes back as one of four decisions:

    ALLOW                     execute as proposed
    BLOCK                     never execute, record why
    MODIFY_ARGUMENTS          execute the repaired arguments
    REQUIRE_HUMAN_APPROVAL    queue for a person, execute nothing yet

Profiles exist so the evaluation can compare a baseline agent, a rule-only
policy and the full framework against identical inputs.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from pydantic import ValidationError

from app.config import Settings, get_settings
from app.db import log_audit
from app.gateway import rules
from app.gateway import provenance
from app.gateway.judge import JudgeVerdict, LLMJudge
from app.llm import LLMClient
from app.schemas import ALLOW, APPROVAL, BLOCK, MODIFY, TOOL_ARG_MODELS

PROFILES = ("baseline", "rules", "full")


@dataclass
class GatewayResult:
    tool: str
    decision: str
    risk_score: int
    reasons: list[dict]
    arguments: dict
    original_arguments: dict
    checks: list[dict] = field(default_factory=list)
    trust: dict = field(default_factory=dict)
    judge: dict = field(default_factory=dict)
    latency_ms: float = 0.0
    profile: str = "full"
    modified: bool = False
    block_code: str = ""
    audit_id: int | None = None

    @property
    def allowed(self) -> bool:
        return self.decision in (ALLOW, MODIFY)

    @property
    def needs_approval(self) -> bool:
        return self.decision == APPROVAL

    @property
    def blocked(self) -> bool:
        return self.decision == BLOCK

    def as_dict(self) -> dict:
        return {
            "tool": self.tool,
            "decision": self.decision,
            "risk_score": self.risk_score,
            "reasons": self.reasons,
            "arguments": self.arguments,
            "original_arguments": self.original_arguments,
            "checks": self.checks,
            "trust": self.trust,
            "judge": self.judge,
            "latency_ms": round(self.latency_ms, 3),
            "profile": self.profile,
            "modified": self.modified,
            "block_code": self.block_code,
            "audit_id": self.audit_id,
        }


class PolicyGateway:
    def __init__(
        self,
        profile: str | None = None,
        settings: Settings | None = None,
        log_to_db: bool = True,
        llm: LLMClient | None = None,
    ):
        self.settings = settings or get_settings()
        chosen = (profile or self.settings.profile or "full").lower()
        self.profile = chosen if chosen in PROFILES else "full"
        self.log_to_db = log_to_db
        self.judge = LLMJudge(self.settings, llm=llm)

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #

    def evaluate(
        self,
        *,
        role: str,
        task: str,
        tool: str,
        arguments: dict | None,
        context: list | None = None,
        session_id: str = "",
        log: bool | None = None,
    ) -> GatewayResult:
        started = time.perf_counter()
        task = task or ""
        original = dict(arguments or {})
        args = dict(original)
        reasons: list[dict] = []
        checks: list[dict] = []
        modifications: list[tuple[str, str]] = []

        items = provenance.normalize_context(context)
        trust = provenance.trust_labels(items)
        untrusted_blob = provenance.untrusted_text(items)

        def add_reason(code: str, message: str, weight: int = 0, severity: str = "info") -> None:
            reasons.append({"code": code, "message": message, "weight": weight, "severity": severity})

        def add_check(name: str, status: str, detail: str = "") -> None:
            checks.append({"name": name, "status": status, "detail": detail})

        block_code = ""
        block_message = ""

        def block(code: str, message: str, weight: int = 70) -> None:
            nonlocal block_code, block_message
            if not block_code:
                block_code, block_message = code, message
            add_reason(code, message, weight, "critical")

        # ---------------------------------------------------------- #
        # 0. Baseline agent: no protection at all (for comparison)
        # ---------------------------------------------------------- #
        if self.profile == "baseline":
            elapsed = (time.perf_counter() - started) * 1000
            result = GatewayResult(
                tool=str(tool),
                decision=ALLOW,
                risk_score=0,
                reasons=[{"code": "baseline", "message": "Baseline agent: policy checks disabled", "weight": 0, "severity": "info"}],
                arguments=args,
                original_arguments=original,
                checks=[{"name": "policy", "status": "skipped", "detail": "baseline profile"}],
                trust=trust,
                judge={"verdict": "skipped", "risk": 0, "engine": "none", "rationale": "baseline profile"},
                latency_ms=elapsed,
                profile=self.profile,
            )
            self._maybe_log(result, role, task, session_id, log)
            return result

        # ---------------------------------------------------------- #
        # 1. Tool allowlist + role permissions
        # ---------------------------------------------------------- #
        tool_key = str(tool or "").strip().lower()
        role_key = str(role or "guest").strip().lower()
        if role_key not in rules.ROLES:
            add_reason("unknown_role", f"Unknown role '{role_key}', treated as guest", 0, "warning")
            role_key = "guest"

        if tool_key not in rules.TOOL_ROLES:
            block("unknown_tool", f"Tool '{tool_key or '(empty)'}' is not on the global allowlist", 90)
            add_check("tool_allowlist", "fail", "unknown tool")
        else:
            add_check("tool_allowlist", "pass", f"{tool_key} is registered")

        if tool_key in rules.TOOL_ROLES:
            allowed_roles = rules.TOOL_ROLES[tool_key]
            if role_key not in allowed_roles:
                block(
                    "role_denied",
                    f"Role '{role_key}' may not call '{tool_key}' (allowed: {', '.join(sorted(allowed_roles))})",
                    80,
                )
                add_check("rbac", "fail", f"{role_key} -> {tool_key} denied")
            else:
                add_check("rbac", "pass", f"{role_key} -> {tool_key} permitted")

        # ---------------------------------------------------------- #
        # 2. JSON argument validation
        # ---------------------------------------------------------- #
        model = TOOL_ARG_MODELS.get(tool_key)
        if model is not None:
            if tool_key == "draft_email":
                hidden = [key for key in ("cc", "bcc") if str(args.get(key) or "").strip()]
                if hidden:
                    block("hidden_recipients", f"Hidden recipient field(s) {', '.join(hidden)} are not allowed", 75)

            known = set(model.model_fields)
            dropped = sorted(key for key in args if key not in known)
            filtered = {key: value for key, value in args.items() if key in known}

            try:
                parsed = model(**filtered)
                args = parsed.model_dump()
                add_check("argument_schema", "pass", "arguments match the tool schema")
                if parsed.model_dump() != filtered:
                    modifications.append(("coerced_arguments", "Coerced argument values to schema types"))
            except ValidationError as exc:
                details = "; ".join(
                    f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
                )
                block("invalid_arguments", f"Arguments failed schema validation — {details}", 65)
                add_check("argument_schema", "fail", details)
                args = filtered

            if dropped:
                modifications.append(("dropped_arguments", f"Dropped unsupported argument(s): {', '.join(dropped)}"))
        else:
            add_check("argument_schema", "fail", "no schema for tool")

        # ---------------------------------------------------------- #
        # 3. File path safety
        # ---------------------------------------------------------- #
        if tool_key == "read_file" and model is not None:
            info = rules.inspect_path(self.settings.workspace, str(args.get("path", "")))
            if not info["ok"]:
                block(info["code"], info["reason"], 80)
                add_check("file_path_safety", "fail", info["reason"])
            else:
                add_check("file_path_safety", "pass", info["normalized"])
                if info["modified"]:
                    args["path"] = info["normalized"]
                    modifications.append(("path_normalized", f"Normalised path to '{info['normalized']}'"))

        # ---------------------------------------------------------- #
        # 4. SQL safety
        # ---------------------------------------------------------- #
        if tool_key == "query_database" and model is not None:
            info = rules.inspect_sql(str(args.get("sql", "")), self.settings.sql_row_limit)
            if not info["ok"]:
                block(info["code"], info["reason"], 80)
                add_check("sql_safety", "fail", info["reason"])
            else:
                tables = ", ".join(sorted({t.split(".")[-1] for t in info["tables"]})) or "none"
                add_check("sql_safety", "pass", f"read-only SELECT on {tables}")
                if info["modified"]:
                    args["sql"] = info["sql"]
                    modifications.append(("sql_repair", info["reason"]))

        # ---------------------------------------------------------- #
        # 5. Email recipient safety
        # ---------------------------------------------------------- #
        if tool_key == "draft_email" and model is not None:
            info = rules.inspect_email(str(args.get("to", "")), self.settings)
            if not info["ok"]:
                block(info["code"], info["reason"], 80)
                add_check("email_recipient", "fail", info["reason"])
            else:
                add_check("email_recipient", "pass", info["recipients"][0])

            secret = rules.secret_in_text(f"{args.get('subject', '')}\n{args.get('body', '')}")
            if secret:
                block("secret_in_draft", f"Draft content looks like it contains a {secret}", 75)
                add_check("secret_scan", "fail", secret)
            else:
                add_check("secret_scan", "pass", "no credentials in the draft body")

        # ---------------------------------------------------------- #
        # 6. Prompt-injection detection (rules + provenance)
        # ---------------------------------------------------------- #
        injection = provenance.scan_untrusted(items)
        user_injection = provenance.scan_text(task)
        injection_score = max(injection.score, user_injection.score)

        if injection.detected:
            add_reason(
                "untrusted_instructions",
                f"Untrusted content contains {len(injection.flags)} injection signature(s) "
                f"(score {injection.score}/100): {injection.flags[0]['label']}",
                injection.score,
                "warning",
            )
            add_check("injection_scan", "fail", f"{len(injection.flags)} signature(s), score {injection.score}")
        elif user_injection.detected:
            add_reason(
                "user_injection",
                f"The user message itself contains injection patterns (score {user_injection.score}/100)",
                user_injection.score,
                "warning",
            )
            add_check("injection_scan", "fail", f"user text score {user_injection.score}")
        else:
            add_check("injection_scan", "pass", "no injection signatures")

        if injection.has_dangerous_instruction:
            add_reason(
                "untrusted_action_instruction",
                "Untrusted content contains an action instruction (email/send/upload/delete)",
                20,
                "warning",
            )

        trust.update(
            {
                "user_task": "trusted",
                "injection_score": injection_score,
                "untrusted_sources": trust.get("untrusted_sources", []),
                "flags": [flag["code"] for flag in injection.flags] + [f"user:{f['code']}" for f in user_injection.flags],
            }
        )

        # ---------------------------------------------------------- #
        # 7. Task/action alignment + argument provenance
        # ---------------------------------------------------------- #
        origins = provenance.argument_provenance(args, task, untrusted_blob)
        if origins:
            described = ", ".join(f"{hit['kind']} '{hit['value']}'" for hit in origins[:3])
            add_reason(
                "untrusted_arguments",
                f"Argument values come only from untrusted content: {described}",
                30,
                "warning",
            )
            add_check("argument_provenance", "fail", described)
        else:
            add_check("argument_provenance", "pass", "arguments trace back to the user task")

        intents = rules.detect_intents(task)
        task_mismatch = bool(intents) and tool_key not in intents
        if not intents:
            add_reason("weak_task_signal", "User task gives no clear tool intent", 10, "warning")
            add_check("task_alignment", "warn", "no intent keywords in task")
        elif task_mismatch:
            add_reason(
                "task_mismatch",
                f"'{tool_key}' is not implied by the user task (intent: {', '.join(sorted(intents))})",
                35,
                "warning",
            )
            add_check("task_alignment", "fail", f"task implies {sorted(intents)}")
        else:
            add_check("task_alignment", "pass", f"task implies {tool_key}")

        # ---------------------------------------------------------- #
        # 8. LLM-as-judge risk score (full profile only)
        # ---------------------------------------------------------- #
        dangerous = tool_key in rules.DANGEROUS_TOOLS
        if self.profile == "full":
            verdict: JudgeVerdict = self.judge.evaluate(
                task=task,
                tool=tool_key,
                arguments=args,
                intents=intents,
                injection_score=injection_score,
                untrusted_instructions=injection.detected or user_injection.detected,
                arg_from_untrusted=bool(origins),
            )
            add_check("llm_judge", "warn" if verdict.risk >= 40 else "pass", f"risk {verdict.risk} ({verdict.engine})")
        else:
            verdict = JudgeVerdict(risk=0, verdict="skipped", rationale="rules-only profile", engine="none")
            add_check("llm_judge", "skipped", "rules-only profile")

        judge_payload = verdict.as_dict()

        # ---------------------------------------------------------- #
        # 9. Risk score + decision
        # ---------------------------------------------------------- #
        if self.profile == "rules":
            risk = 5
            risk += min(40, round(injection_score * 0.5))
            risk += 20 if dangerous else 0
            risk += 15 if origins else 0
            risk = max(0, min(100, risk))
        else:
            risk = 5
            risk += round(verdict.risk * 0.45)
            risk += min(35, round(injection_score * 0.4))
            risk += 25 if origins else 0
            risk += 20 if task_mismatch else 0
            risk += 10 if dangerous else 0
            risk = max(0, min(100, risk))

        if block_code:
            decision = BLOCK
            risk = 100
        elif self.profile == "rules":
            if injection_score >= 55 and dangerous:
                decision = BLOCK
                add_reason("injection_with_dangerous_tool", "Injection detected while calling a dangerous tool", 40, "critical")
            elif injection_score >= 55:
                decision = APPROVAL
                add_reason("injection_review", "Injection detected; action queued for human review", 25, "warning")
            elif modifications:
                decision = MODIFY
            else:
                decision = ALLOW
        else:
            if dangerous and origins:
                decision = BLOCK
                add_reason("exfiltration_guard", "Dangerous tool arguments were copied from untrusted content", 50, "critical")
            elif injection_score >= 60 and dangerous:
                decision = BLOCK
                add_reason("injection_with_dangerous_tool", "Injection detected while calling a dangerous tool", 45, "critical")
            elif origins and tool_key == "read_file":
                decision = APPROVAL
                add_reason("untrusted_file_target", "File target originates from untrusted content", 25, "warning")
            elif risk >= self.settings.risk_block_min:
                decision = BLOCK
            elif risk >= self.settings.risk_approval_min:
                decision = APPROVAL
            elif risk >= 40:
                decision = MODIFY if modifications else APPROVAL
            elif modifications:
                decision = MODIFY
            elif dangerous and role_key == "admin":
                decision = APPROVAL
                add_reason(
                    "dangerous_action_approval",
                    "Admin may draft email, but every outbound action needs human approval",
                    20,
                    "warning",
                )
            else:
                decision = ALLOW

        if modifications and decision in (ALLOW, MODIFY):
            for code, message in modifications:
                add_reason(code, message, 5, "info")

        if decision == ALLOW and not reasons:
            add_reason("policy_clean", "All policy checks passed", 0, "info")
        if block_message and not any(r["code"] == block_code for r in reasons):
            add_reason(block_code, block_message, 100, "critical")

        elapsed = (time.perf_counter() - started) * 1000
        result = GatewayResult(
            tool=tool_key,
            decision=decision,
            risk_score=int(risk),
            reasons=reasons,
            arguments=args,
            original_arguments=original,
            checks=checks,
            trust=trust,
            judge=judge_payload,
            latency_ms=elapsed,
            profile=self.profile,
            modified=bool(modifications),
            block_code=block_code,
        )
        self._maybe_log(result, role_key, task, session_id, log)
        return result

    # ------------------------------------------------------------------ #
    # Audit
    # ------------------------------------------------------------------ #

    def _maybe_log(self, result: GatewayResult, role: str, task: str, session_id: str, log: bool | None) -> None:
        should_log = self.log_to_db if log is None else log
        if not should_log:
            return
        try:
            result.audit_id = log_audit(
                session_id=session_id,
                role=role,
                task=task,
                tool=result.tool,
                arguments=result.arguments,
                decision=result.decision,
                risk_score=result.risk_score,
                reasons=result.reasons,
                trust=result.trust,
                judge=result.judge,
                latency_ms=result.latency_ms,
                executed=False,
                result_preview="",
                profile=result.profile,
            )
        except Exception:  # pragma: no cover - auditing must never break an agent
            result.audit_id = None
