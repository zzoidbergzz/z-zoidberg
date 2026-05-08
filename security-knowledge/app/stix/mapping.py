from app.models.entities import EntityKind

ENTITY_KIND_TO_STIX_TYPE = {
    EntityKind.cve: "vulnerability",
    EntityKind.vulnerability: "vulnerability",
    EntityKind.malware: "malware",
    EntityKind.actor: "threat-actor",
    EntityKind.tool: "tool",
    EntityKind.ip_address: "indicator",
    EntityKind.domain: "indicator",
    EntityKind.url: "indicator",
    EntityKind.hash: "indicator",
    EntityKind.campaign: "campaign",
    EntityKind.attack_pattern: "attack-pattern",
    EntityKind.indicator: "indicator",
    EntityKind.report: "report",
    EntityKind.organization: "identity",
    EntityKind.other: "x-custom-object",
}

STIX_INDICATOR_PATTERNS = {
    "ip_address": "[ipv4-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "hash": "[file:hashes.MD5 = '{value}']",
    "indicator": "[x-indicator:value = '{value}']",
}
