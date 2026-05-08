PIVOT_CONFIG = {
    "max_manual_depth": 4,
    "max_nodes_per_query": 300,
    "auto_pivot_types": {"resolves_to", "hosts", "communicates_with", "related_to", "uses", "attributed_to"},
    "skip_common_entities": set(),
}
