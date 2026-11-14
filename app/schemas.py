"""Decision vocabulary and JSON schemas for every tool call.

The gateway validates raw LLM arguments against these models *before* a tool
ever runs.  Validation is deliberately strict on types and lengths, and the
gateway additionally rejects unknown fields (or repairs the call by dropping
them, depending on the profile).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

ALLOW = "ALLOW"
BLOCK = "BLOCK"
MODIFY = "MODIFY_ARGUMENTS"
APPROVAL = "REQUIRE_HUMAN_APPROVAL"
DECISIONS = (ALLOW, BLOCK, MODIFY, APPROVAL)


class ToolArgs(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)


class ReadFileArgs(ToolArgs):
    path: str = Field(min_length=1, max_length=400)


class WebSearchArgs(ToolArgs):
    query: str = Field(min_length=1, max_length=300)
    max_results: int = Field(default=3, ge=1, le=10)


class QueryDatabaseArgs(ToolArgs):
    sql: str = Field(min_length=1, max_length=2000)


class DraftEmailArgs(ToolArgs):
    to: str = Field(min_length=3, max_length=200)
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=6000)


TOOL_ARG_MODELS: dict[str, type[ToolArgs]] = {
    "read_file": ReadFileArgs,
    "web_search": WebSearchArgs,
    "query_database": QueryDatabaseArgs,
    "draft_email": DraftEmailArgs,
}
