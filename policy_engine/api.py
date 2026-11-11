from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from policy_engine.engine import Decision, Policy, Request, evaluate

app = FastAPI(title="Tenant Policy Engine", version="0.1.0")


class Evaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy: Policy
    request: Request


@app.post("/evaluate", response_model=Decision)
def decide(body: Evaluation):
    return evaluate(body.policy, body.request)


@app.get("/health")
def health():
    return {"status": "ok"}
