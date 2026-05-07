import pytest
import uuid
from app.models.entities import Entity, EntityKind
from app.models.claims import Claim
from app.models.auth import Tenant, ApiKey


def test_entity_kind_enum_values():
    assert EntityKind.cve == "cve"
    assert EntityKind.malware == "malware"
    assert EntityKind.actor == "actor"
    assert EntityKind.ip_address == "ip_address"


def test_entity_kind_is_str():
    assert isinstance(EntityKind.cve, str)


def test_all_entity_kinds_present():
    kinds = {k.value for k in EntityKind}
    expected = {"cve", "malware", "actor", "tool", "domain", "url", "hash",
                "campaign", "vulnerability", "indicator", "report"}
    assert expected.issubset(kinds)


def test_entity_table_name():
    assert Entity.__tablename__ == "entities"


def test_claim_table_name():
    assert Claim.__tablename__ == "claims"


def test_tenant_table_name():
    assert Tenant.__tablename__ == "tenants"
