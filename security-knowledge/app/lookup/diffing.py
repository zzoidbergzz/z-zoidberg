from __future__ import annotations
from typing import Any

def _compact(value: Any, max_length: int = 240) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str) and len(value) > max_length:
        return value[:max_length - 3] + "..."
    return value

def json_diff(old: Any, new: Any, path: str = "$", changes: list[dict[str, Any]] | None = None, max_changes: int = 250):
    if changes is None:
        changes = []
    if len(changes) >= max_changes:
        return changes
    if type(old) is not type(new):
        changes.append({"path": path, "change_type": "type_changed", "old": _compact(old), "new": _compact(new)})
        return changes
    if isinstance(old, dict):
        all_keys = sorted(set(old) | set(new))
        for key in all_keys:
            child_path = f"{path}.{key}"
            if key not in old:
                changes.append({"path": child_path, "change_type": "added", "old": None, "new": _compact(new[key])})
            elif key not in new:
                changes.append({"path": child_path, "change_type": "removed", "old": _compact(old[key]), "new": None})
            else:
                json_diff(old[key], new[key], child_path, changes, max_changes)
            if len(changes) >= max_changes:
                break
        return changes
    if isinstance(old, list):
        if old == new:
            return changes
        if len(old) > 20 or len(new) > 20:
            changes.append({"path": path, "change_type": "list_changed", "old_count": len(old), "new_count": len(new)})
            return changes
        for i in range(max(len(old), len(new))):
            child_path = f"{path}[{i}]"
            if i >= len(old):
                changes.append({"path": child_path, "change_type": "added", "old": None, "new": _compact(new[i])})
            elif i >= len(new):
                changes.append({"path": child_path, "change_type": "removed", "old": _compact(old[i]), "new": None})
            else:
                json_diff(old[i], new[i], child_path, changes, max_changes)
            if len(changes) >= max_changes:
                break
        return changes
    if old != new:
        changes.append({"path": path, "change_type": "modified", "old": _compact(old), "new": _compact(new)})
    return changes

def diff_payload(old: Any, new: Any, max_changes: int = 250) -> dict[str, Any]:
    changes = json_diff(old, new, changes=[], max_changes=max_changes)
    summary = {
        "total": len(changes),
        "added": sum(1 for c in changes if c["change_type"] == "added"),
        "removed": sum(1 for c in changes if c["change_type"] == "removed"),
        "modified": sum(1 for c in changes if c["change_type"] in {"modified", "type_changed", "list_changed"}),
        "truncated": len(changes) >= max_changes,
    }
    return {"summary": summary, "changes": changes}
