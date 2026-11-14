"""Public investigation conclusions, not private model reasoning."""
from typing import Literal
from pydantic import BaseModel, Field


class Hypothesis(BaseModel):
    hypothesis: str = Field(min_length=1)
    confidence: Literal['low', 'medium', 'high']
    supporting_evidence: list[str]
    historical_source_ids: list[str]
    similarities: list[str]
    differences: list[str]
    uncertainty: str
    basis: str = Field(min_length=1)


class InvestigationCheck(BaseModel):
    priority: int = Field(ge=1)
    check: str = Field(min_length=1)
    expected_observation: str = Field(min_length=1)
    safe_remediation: str
    risk_or_impact: str = Field(min_length=1)
    verification_required: str = Field(min_length=1)


class InvestigationReport(BaseModel):
    ai_reasoning: list[Hypothesis] = Field(min_length=1)
    recommended_investigation: list[InvestigationCheck] = Field(min_length=1)
    failed_approaches: list[str]
    missing_evidence: list[str]
    resolution_verification: list[str] = Field(min_length=1)
