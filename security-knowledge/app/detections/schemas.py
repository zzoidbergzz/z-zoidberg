from pydantic import BaseModel
from typing import Optional
import uuid


class DetectionRuleCreate(BaseModel):
    name: str
    rule_type: str = "sigma"
    rule_yaml: str
    description: Optional[str] = None
    tags: list[str] = []
    severity: str = "medium"


class DetectionRuleOut(BaseModel):
    id: uuid.UUID
    name: str
    rule_type: str
    rule_yaml: str
    description: Optional[str]
    severity: str
    tags: list[str]
    tenant_id: uuid.UUID

    model_config = {"from_attributes": True}
