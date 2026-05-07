import pytest
from unittest.mock import AsyncMock, MagicMock
from app.detections.schemas import DetectionRuleCreate


def test_detection_rule_create_defaults():
    rule = DetectionRuleCreate(
        name="Test Rule",
        rule_yaml="title: Test\ndetection:\n  condition: selection"
    )
    assert rule.rule_type == "sigma"
    assert rule.severity == "medium"


def test_detection_rule_create_custom():
    rule = DetectionRuleCreate(
        name="Yara Rule",
        rule_type="yara",
        rule_yaml='rule test { condition: false }',
        severity="high",
        tags=["malware", "ransomware"],
    )
    assert rule.rule_type == "yara"
    assert "malware" in rule.tags


@pytest.mark.asyncio
async def test_list_detections_empty(client, mock_db):
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_db.execute = AsyncMock(return_value=mock_result)
    resp = await client.get("/api/v1/detections/")
    assert resp.status_code == 200
    assert resp.json() == []
