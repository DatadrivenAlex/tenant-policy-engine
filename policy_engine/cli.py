import argparse
import json
import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

from policy_engine.engine import Policy, Request, evaluate


def main():
    parser = argparse.ArgumentParser(description="Evaluate a trusted local policy and request")
    parser.add_argument("policy", type=Path)
    parser.add_argument("request", type=Path)
    args = parser.parse_args()
    try:
        policy = Policy.model_validate(yaml.safe_load(args.policy.read_text()))
        request = Request.model_validate(json.loads(args.request.read_text()))
        decision = evaluate(policy, request)
    except (OSError, ValueError, yaml.YAMLError, ValidationError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(decision.model_dump_json(indent=2))
    return 0 if decision.allowed else 1
