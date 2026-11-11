import copy
import json
import subprocess

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from policy_engine.api import app
from policy_engine.engine import Policy, Request, evaluate

BASE = {
    "subject": {"tenant": "a", "roles": ["reader"], "attributes": {"level": "internal"}},
    "resource": {"tenant": "a", "type": "report"},
    "action": "read:summary",
    "at": "2026-06-01T12:00:00Z",
}
RULE = {
    "id": "read",
    "effect": "allow",
    "roles": ["reader"],
    "actions": ["read:*"],
    "resource_types": ["report"],
}


def run(rules=None, request=None):
    return evaluate(
        Policy.model_validate({"rules": rules if rules is not None else [RULE]}),
        Request.model_validate(request or BASE),
    )


def test_allow():
    assert run().allowed
    assert run().matched_rules == ["read"]


def test_empty_default_deny():
    assert run([]).reason == "default_deny"


def test_tenant_boundary():
    req = copy.deepcopy(BASE)
    req["resource"]["tenant"] = "b"
    assert run(request=req).reason == "tenant_mismatch"


@pytest.mark.parametrize(
    "rules",
    [[RULE, dict(RULE, id="block", effect="deny")], [dict(RULE, id="block", effect="deny"), RULE]],
)
def test_deny_order_independent(rules):
    result = run(rules)
    assert result.reason == "explicit_deny" and result.matched_rules == ["block", "read"]


@pytest.mark.parametrize(
    "path,value",
    [
        ("roles", ["other"]),
        ("actions", ["write:*"]),
        ("resource_types", ["invoice"]),
        ("required_attributes", {"level": "secret"}),
    ],
)
def test_nonmatching(path, value):
    assert not run([dict(RULE, **{path: value})]).allowed


def test_required_attribute_matches():
    assert run([dict(RULE, required_attributes={"level": "internal"})]).allowed


def test_missing_attribute():
    assert not run([dict(RULE, required_attributes={"missing": "x"})]).allowed


def test_no_roles():
    req = copy.deepcopy(BASE)
    req["subject"]["roles"] = []
    assert not run([dict(RULE, roles=["*"])], req).allowed


@pytest.mark.parametrize(
    "at,allowed",
    [
        ("2026-06-01T11:59:59Z", False),
        ("2026-06-01T12:00:00Z", True),
        ("2026-06-01T12:59:59Z", True),
        ("2026-06-01T13:00:00Z", False),
        ("2026-06-01T14:00:00+02:00", True),
    ],
)
def test_time_window(at, allowed):
    req = copy.deepcopy(BASE)
    req["at"] = at
    assert (
        run(
            [dict(RULE, valid_from="2026-06-01T12:00:00Z", valid_until="2026-06-01T13:00:00Z")], req
        ).allowed
        is allowed
    )


@pytest.mark.parametrize("at", ["2026-01-01T12:00:00", "yesterday", "2026-13-01T00:00:00Z"])
def test_bad_time(at):
    with pytest.raises(ValidationError):
        Request.model_validate(dict(BASE, at=at))


def test_duplicate_ids():
    with pytest.raises(ValidationError):
        Policy.model_validate({"rules": [RULE, RULE]})


@pytest.mark.parametrize(
    "change",
    [
        {"effect": "permit"},
        {"roles": []},
        {"actions": [""]},
        {"unknown": True},
        {"valid_from": "2026-01-02T00:00:00Z", "valid_until": "2026-01-01T00:00:00Z"},
    ],
)
def test_invalid_policy(change):
    with pytest.raises(ValidationError):
        Policy.model_validate({"rules": [dict(RULE, **change)]})


def test_case_sensitive():
    assert not run([dict(RULE, actions=["READ:*"])]).allowed


def test_no_mutation():
    before = copy.deepcopy(BASE)
    run()
    assert BASE == before


def test_api():
    c = TestClient(app)
    assert c.post("/evaluate", json={"policy": {"rules": [RULE]}, "request": BASE}).json()[
        "allowed"
    ]
    assert (
        c.post(
            "/evaluate", json={"policy": {"rules": [RULE]}, "request": dict(BASE, at="bad")}
        ).status_code
        == 422
    )
    assert c.get("/health").status_code == 200


def test_cli_exit_codes(tmp_path):
    p = tmp_path / "p.yml"
    q = tmp_path / "q.json"
    p.write_text(json.dumps({"rules": [RULE]}))
    q.write_text(json.dumps(BASE))
    assert (
        subprocess.run(
            ["policy-check", str(p), str(q)], check=False, capture_output=True
        ).returncode
        == 0
    )
    p.write_text("rules: []")
    assert (
        subprocess.run(
            ["policy-check", str(p), str(q)], check=False, capture_output=True
        ).returncode
        == 1
    )
    p.write_text("bad: yaml")
    assert (
        subprocess.run(
            ["policy-check", str(p), str(q)], check=False, capture_output=True
        ).returncode
        == 2
    )
