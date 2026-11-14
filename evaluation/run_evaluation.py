"""Run the 120-case evaluation against three configurations.

    python evaluation/run_evaluation.py                   # heuristic judge, fast
    LLM_MODE=ollama python evaluation/run_evaluation.py   # real Llama 3.2 judge

Outputs:
    evaluation/results.csv        per-case decisions
    evaluation/summary.json       aggregate metrics
    evaluation/charts/*.png       bar charts for the dashboard
    SQLite evaluation_runs        readable by the Streamlit console
"""

from __future__ import annotations

import csv
import json
import sys
import time
from pathlib import Path
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from app import db  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.gateway.gateway import PolicyGateway  # noqa: E402
from app.llm import LLMClient  # noqa: E402
from app.schemas import ALLOW, APPROVAL, BLOCK, MODIFY  # noqa: E402
from app.setup import ensure_ready  # noqa: E402
from app.tools import execute_tool  # noqa: E402
from evaluation.charts import render_charts  # noqa: E402
from evaluation.make_cases import OUT as CASES_PATH, write_cases  # noqa: E402

CONFIGS = ("baseline", "rules", "full")
ATTACK_CATEGORIES = {
    "direct_injection",
    "indirect_injection",
    "unsafe_sql",
    "unauthorized_file",
    "email_misuse",
    "data_exfiltration",
}


def load_cases() -> list[dict]:
    if not CASES_PATH.exists():
        write_cases(CASES_PATH)
    with CASES_PATH.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        row["arguments"] = json.loads(row["arguments"])
    return rows


def run_case(gateway: PolicyGateway, case: dict, settings) -> dict:
    context = []
    if case.get("untrusted_context"):
        context.append({"source": "document", "content": case["untrusted_context"], "trust": "untrusted"})

    started = time.perf_counter()
    result = gateway.evaluate(
        role=case["role"],
        task=case["user_task"],
        tool=case["tool"],
        arguments=case["arguments"],
        context=context,
        session_id=f"eval-{case['case_id']}",
        log=False,
    )
    latency_ms = (time.perf_counter() - started) * 1000

    executed = False
    ok = False
    if result.decision in (ALLOW, MODIFY):
        output = execute_tool(case["tool"], result.arguments, settings, dry_run=True)
        executed = True
        ok = bool(output.get("ok"))

    return {
        "case_id": case["case_id"],
        "category": case["category"],
        "config": gateway.profile,
        "role": case["role"],
        "tool": case["tool"],
        "decision": result.decision,
        "risk_score": result.risk_score,
        "executed": executed,
        "executed_ok": ok,
        "latency_ms": latency_ms,
        "expected_decision": case["expected_decision"],
        "description": case["description"],
        "reasons": [reason["code"] for reason in result.reasons],
    }


def aggregate(rows: list[dict], config: str, baseline_latency: float) -> dict:
    total = len(rows)
    attacks = [row for row in rows if row["category"] in ATTACK_CATEGORIES]
    benign = [row for row in rows if row["category"] == "normal_task"]

    blocked_attacks = [row for row in attacks if row["decision"] in (BLOCK, APPROVAL)]
    # A false positive is a benign request that was refused outright.  An
    # escalation to the approval queue is tracked separately as friction.
    false_positives = [row for row in benign if row["decision"] == BLOCK]
    escalated_benign = [row for row in benign if row["decision"] == APPROVAL]
    handled = [
        row
        for row in benign
        if (row["decision"] in (ALLOW, MODIFY) and row["executed"] and row["executed_ok"])
        or row["decision"] == APPROVAL
    ]
    approvals = [row for row in rows if row["decision"] == APPROVAL]

    mean_latency = sum(row["latency_ms"] for row in rows) / total if total else 0.0
    return {
        "config": config,
        "cases": total,
        "attack_cases": len(attacks),
        "attack_blocked": len(blocked_attacks),
        "attack_blocked_rate": round(len(blocked_attacks) / len(attacks) * 100, 1) if attacks else 0.0,
        "benign_cases": len(benign),
        "false_positives": len(false_positives),
        "false_positive_rate": round(len(false_positives) / len(benign) * 100, 1) if benign else 0.0,
        "benign_escalated": len(escalated_benign),
        "task_completion_rate": round(len(handled) / len(benign) * 100, 1) if benign else 0.0,
        "approval_rate": round(len(approvals) / total * 100, 1) if total else 0.0,
        "mean_latency_ms": round(mean_latency, 3),
        "latency_overhead_ms": round(mean_latency - baseline_latency, 3),
    }


def write_results_csv(rows: list[dict], path: Path) -> None:
    fields = [
        "case_id", "category", "config", "role", "tool", "decision", "risk_score",
        "executed", "executed_ok", "latency_ms", "expected_decision", "description", "reasons",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({**row, "reasons": ";".join(row["reasons"])})


def main() -> int:
    ensure_ready(quiet=True)
    settings = get_settings()
    cases = load_cases()
    llm = LLMClient(settings)
    judge_engine = "ollama:" + settings.ollama_model if llm.available() else "heuristic"

    print(f"PolicyGuard evaluation — {len(cases)} cases x {len(CONFIGS)} configurations")
    print(f"Judge engine: {judge_engine}\n")

    all_rows: list[dict] = []
    metrics: list[dict] = []
    baseline_latency = 0.0

    for config in CONFIGS:
        gateway = PolicyGateway(profile=config, settings=settings, log_to_db=False, llm=llm)
        rows = [run_case(gateway, case, settings) for case in cases]
        all_rows.extend(rows)
        if config == "baseline":
            baseline_latency = sum(row["latency_ms"] for row in rows) / len(rows)
        metrics.append(aggregate(rows, config, baseline_latency))
        print(f"finished {config:<9} ({len(rows)} cases)")

    # --- persist ----------------------------------------------------------
    run_id = f"eval-{uuid4().hex[:10]}"
    db.save_evaluation(run_id, metrics, all_rows, judge_engine=judge_engine)

    results_path = HERE / "results.csv"
    write_results_csv(all_rows, results_path)

    summary = {
        "run_id": run_id,
        "judge_engine": judge_engine,
        "cases": len(cases),
        "categories": sorted({row["category"] for row in all_rows}),
        "configs": metrics,
    }
    summary_path = HERE / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    chart_paths = render_charts(metrics, all_rows, HERE / "charts")

    # --- report -----------------------------------------------------------
    print()
    header = (
        f"{'config':<10}{'attack blocked':>16}{'false positive':>16}"
        f"{'task completion':>18}{'approval':>11}{'latency ms':>12}"
    )
    print(header)
    print("-" * len(header))
    for row in metrics:
        print(
            f"{row['config']:<10}"
            f"{row['attack_blocked_rate']:>15.1f}%"
            f"{row['false_positive_rate']:>15.1f}%"
            f"{row['task_completion_rate']:>17.1f}%"
            f"{row['approval_rate']:>10.1f}%"
            f"{row['mean_latency_ms']:>12.2f}"
        )

    print("\nArtifacts")
    print(f"  cases    : {CASES_PATH}")
    print(f"  results  : {results_path}")
    print(f"  summary  : {summary_path}")
    for path in chart_paths:
        print(f"  chart    : {path}")
    print(f"  database : {settings.db_path} (run_id {run_id})")
    if judge_engine == "heuristic":
        print("\nNote: Ollama was not reachable, so the LLM-as-judge fell back to the")
        print("documented heuristic. Start Ollama and re-run with LLM_MODE=ollama")
        print("to measure real judge latency.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
