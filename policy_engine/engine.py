"""Pure policy evaluation: deny overrides allow; tenant isolation is always enforced."""

from datetime import datetime
from fnmatch import fnmatchcase
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Rule(StrictModel):
    id: str = Field(min_length=1, max_length=120)
    effect: Literal["allow", "deny"]
    roles: list[str] = Field(min_length=1)
    actions: list[str] = Field(min_length=1)
    resource_types: list[str] = Field(min_length=1)
    required_attributes: dict[str, str] = Field(default_factory=dict)
    valid_from: str | None = None
    valid_until: str | None = None

    @model_validator(mode="after")
    def validate_rule(self):
        for values in (self.roles, self.actions, self.resource_types):
            if any(not item.strip() for item in values):
                raise ValueError("Empty match patterns are not allowed")
        start = instant(self.valid_from) if self.valid_from else None
        end = instant(self.valid_until) if self.valid_until else None
        if start and end and start >= end:
            raise ValueError("valid_from must precede valid_until")
        return self


class Policy(StrictModel):
    rules: list[Rule]

    @model_validator(mode="after")
    def unique_ids(self):
        ids = [rule.id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("Rule IDs must be unique")
        return self


class Subject(StrictModel):
    tenant: str = Field(min_length=1)
    roles: list[str]
    attributes: dict[str, str] = Field(default_factory=dict)


class Resource(StrictModel):
    tenant: str = Field(min_length=1)
    type: str = Field(min_length=1)


class Request(StrictModel):
    subject: Subject
    resource: Resource
    action: str = Field(min_length=1)
    at: str

    @model_validator(mode="after")
    def aware_time(self):
        instant(self.at)
        return self


class Decision(StrictModel):
    allowed: bool
    reason: Literal["tenant_mismatch", "explicit_deny", "explicit_allow", "default_deny"]
    matched_rules: list[str]


def instant(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("Expected an ISO 8601 timestamp") from error
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("Timestamp must include a timezone")
    return result


def evaluate(policy: Policy, request: Request) -> Decision:
    if request.subject.tenant != request.resource.tenant:
        return Decision(allowed=False, reason="tenant_mismatch", matched_rules=[])
    now = instant(request.at)
    matched = []
    for rule in policy.rules:
        if not any(role in rule.roles or "*" in rule.roles for role in request.subject.roles):
            continue
        if not any(fnmatchcase(request.action, pattern) for pattern in rule.actions):
            continue
        if not any(fnmatchcase(request.resource.type, pattern) for pattern in rule.resource_types):
            continue
        if any(request.subject.attributes.get(k) != v for k, v in rule.required_attributes.items()):
            continue
        if rule.valid_from and now < instant(rule.valid_from):
            continue
        if rule.valid_until and now >= instant(rule.valid_until):
            continue
        matched.append(rule)
    ids = sorted(rule.id for rule in matched)
    if any(rule.effect == "deny" for rule in matched):
        return Decision(allowed=False, reason="explicit_deny", matched_rules=ids)
    if matched:
        return Decision(allowed=True, reason="explicit_allow", matched_rules=ids)
    return Decision(allowed=False, reason="default_deny", matched_rules=[])
