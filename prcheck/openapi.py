"""OpenAPI changelog: semantic diff of two OpenAPI v2/v3 specs.

Parsed with PyYAML (safe). Reports:

* endpoint added / removed / modified
* operation-level summary change
* parameter added / removed / required / schema-change
* schema (component) added / removed / modified, with attribute-level detail

The ``breaking`` flag drives version inference:

* major bump  -> any breaking change
* minor bump  -> endpoints/params/schemas added (non-breaking additions)
* patch bump  -> descriptive-only changes
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import yaml

# -------------------------------------------------------------------------
# spec loading (v2 / v3 friendly)
# -------------------------------------------------------------------------


class SpecVersion(Enum):
    SWAGGER_2 = "swagger2"
    OPENAPI_3 = "openapi3"


@dataclass
class Spec:
    raw: dict
    version: SpecVersion
    source: str = ""

    @property
    def info(self) -> dict:
        return self.raw.get("info", {}) or {}

    @property
    def title(self) -> str:
        return str(self.info.get("title", ""))

    @property
    def version_string(self) -> str:
        return str(self.info.get("version", ""))

    def paths(self) -> dict:
        return self.raw.get("paths", {}) or {}

    def components_schemas(self) -> dict:
        if self.version == SpecVersion.OPENAPI_3:
            return ((self.raw.get("components") or {}).get("schemas") or {}) or {}
        return self.raw.get("definitions") or {}

    def iter_operations(self):
        """Yield (path, http_method, operation_dict)."""
        for path, item in (self.raw.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            for method in ("get", "post", "put", "patch", "delete", "head", "options"):
                op = item.get(method)
                if isinstance(op, dict):
                    yield path, method, op


def load_spec(text: str, source: str = "") -> Spec:
    """Parse + basic-validate a spec; accept both swagger/oas dict shapes."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ValueError(f"invalid YAML in {source or 'spec'}: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"{source or 'spec'} is not a mapping")
    openapi = data.get("openapi")
    if isinstance(openapi, str):
        return Spec(data, SpecVersion.OPENAPI_3, source)
    swagger = data.get("swagger")
    if isinstance(swagger, str):
        return Spec(data, SpecVersion.SWAGGER_2, source)
    raise ValueError(f"{source or 'spec'}: missing 'openapi'/'swagger' version field")


# -------------------------------------------------------------------------
# change model
# -------------------------------------------------------------------------


@dataclass
class Change:
    kind: str          # "endpoint" | "parameter" | "schema" | "operation" | "info"
    path: str = ""
    method: str = ""
    schema: str = ""
    detail: str = ""
    summary: str = ""
    breaking: bool = False
    severity: str = "low"
    auxiliary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.kind,
            "path": self.path or None,
            "method": self.method or None,
            "schema": self.schema or None,
            "detail": self.detail or None,
            "summary": self.summary,
            "breaking": self.breaking,
            "severity": self.severity,
        }


def _method_label(method: str) -> str:
    return method.upper() if method else ""


def _summarize_endpoint(method: str, path: str, op: dict) -> str:
    s = op.get("summary") or op.get("operationId") or ""
    return f"{_method_label(method)} {path} — {s}".strip()

# -------------------------------------------------------------------------
# comparison engine
# -------------------------------------------------------------------------


def _deep_equals(a: Any, b: Any) -> bool:
    return json.dumps(a, sort_keys=True, default=str) == json.dumps(
        b, sort_keys=True, default=str
    )


def _schema_change_sev(change: dict) -> str:
    if change.get("breaking"):
        return "medium" if change.get("type") == "schema-type-changed" else "low"
    return "low"


def compare_params(old_op: dict, new_op: dict, path: str, method: str) -> list[Change]:
    old_ps = old_op.get("parameters") or []
    new_ps = new_op.get("parameters") or []
    changes: list[Change] = []
    old_by = {_pkey(p): p for p in old_ps}
    new_by = {_pkey(p): p for p in new_ps}

    for key, np in new_by.items():
        op = old_by.get(key)
        if op is None:
            changes.append(
                Change(
                    kind="parameter",
                    path=path,
                    method=method,
                    detail=f"parameter `{key}` added",
                    summary=f"parameter `{key}` added",
                    breaking=False,
                    severity="low",
                )
            )
            continue
        # same param exists: check required/schema
        if op.get("required") != np.get("required"):
            if np.get("required") and op.get("required") is not True:
                changes.append(
                    Change(
                        kind="parameter",
                        path=path,
                        method=method,
                        detail="required flag flipped",
                        summary=f"parameter `{key}` is now required",
                        breaking=True,
                        severity="high",
                    )
                )
        ns, os_ = np.get("schema"), op.get("schema")
        if ns and os_ and not _deep_equals(ns, os_):
            changes.append(
                Change(
                    kind="parameter",
                    path=path,
                    method=method,
                    detail="schema changed",
                    summary=f"parameter `{key}` schema type/schema changed",
                    breaking=_param_schema_breaking(ns, os_),
                    severity="medium",
                )
            )
    # removed
    for key, op in old_by.items():
        if key not in new_by:
            changes.append(
                Change(
                    kind="parameter",
                    path=path,
                    method=method,
                    detail="parameter removed",
                    summary=f"parameter `{key}` removed",
                    breaking=True,
                    severity="medium",
                )
            )
    return changes


def _pkey(p: dict) -> str:
    loc = "path" if p.get("in") == "path" else (p.get("in") or "query")
    return f'{(p.get("name") or "")}'


def _param_schema_breaking(ns: dict, os_: dict) -> bool:
    if "type" in ns or "type" in os_:
        return ns.get("type") != os_.get("type")
    if "$ref" in ns and "$ref" in os_:
        return ns["$ref"] != os_["$ref"]
    return False


def _compare_schema_attrs(old: dict, new: dict) -> list[tuple[str, Any, Any]]:
    """Yield (propertyOrKey, oldVal, newVal) for changed primitive props."""
    out = []
    for k in set(old) | set(new):
        if k in ("description", "example", "default"):
            continue
        if k in old and k in new and not _deep_equals(old[k], new[k]):
            out.append((k, old[k], new[k]))
    return out


def compare_schemas(old: Spec, new: Spec) -> list[Change]:
    old_s = old.components_schemas()
    new_s = new.components_schemas()
    changes: list[Change] = []
    for name, ns in new_s.items():
        if name not in old_s:
            changes.append(
                Change("schema", schema=name, summary=f"schema `{name}` added", breaking=False)
            )
            continue
        os_ = old_s[name]
        # attribute-level diff
        for attr, old_v, new_v in _compare_schema_attrs(os_, ns):
            changes.append(
                Change(
                    "schema",
                    schema=name,
                    detail=attr,
                    summary=f"schema `{name}`: attribute `{attr}` changed",
                    breaking=_attr_breaking(attr, old_v, new_v),
                    severity="medium",
                )
            )
        # property add/remove/change
        old_props = (os_.get("properties") or {})
        new_props = (ns.get("properties") or {})
        for prop, val in new_props.items():
            if prop not in old_props:
                changes.append(
                    Change(
                        "schema",
                        schema=name,
                        detail=prop,
                        summary=f"schema `{name}`: property `{prop}` added",
                        breaking=False,
                    )
                )
            elif old_props[prop] != val:
                changes.append(
                    Change(
                        "schema",
                        schema=name,
                        detail=prop,
                        summary=f"schema `{name}`: property `{prop}` modified",
                        breaking=_prop_breaking(old_props[prop], val),
                        severity="medium",
                    )
                )
        for prop in old_props:
            if prop not in new_props:
                changes.append(
                    Change(
                        "schema",
                        schema=name,
                        detail=prop,
                        summary=f"schema `{name}`: property `{prop}` removed",
                        breaking=True,
                        severity="medium",
                    )
                )
    for name in old_s:
        if name not in new_s:
            changes.append(
                Change("schema", schema=name, summary=f"schema `{name}` removed", breaking=True)
            )
    return changes


def _attr_breaking(attr: str, old_v: Any, new_v: Any) -> bool:
    if attr in ("type", "required", "enum"):
        return True
    if attr == "additionalProperties":
        return bool(old_v) and not bool(new_v)
    return False


def _prop_breaking(old_prop: Any, new_prop: Any) -> bool:
    if isinstance(old_prop, dict) and isinstance(new_prop, dict):
        if "type" in old_prop and "type" in new_prop and old_prop["type"] != new_prop["type"]:
            return True
        if (old_prop.get("required") or False) and not (new_prop.get("required") or False):
            return True  # not really breaking, keep non-breaking
    if old_prop != new_prop:
        # unknown structural change default non-breaking? conservative:
        return False
    return False


def compare_specs(old: Spec, new: Spec) -> list[Change]:
    """Full semantic diff between two parsed specs."""
    changes: list[Change] = []
    old_paths = old.paths()
    new_paths = new.paths()

    for path, item in new_paths.items():
        for method, op in (item.items() if isinstance(item, dict) else []):
            if method not in _HTTP_METHODS:
                continue
            old_path_item = old_paths.get(path)
            old_op = None
            if isinstance(old_path_item, dict):
                old_op = old_path_item.get(method)
            if old_op is None:
                changes.append(
                    Change(
                        kind="endpoint",
                        path=path,
                        method=method,
                        detail="endpoint added",
                        summary=f"{_method_label(method)} {path} — endpoint added",
                        breaking=False,
                        severity="low",
                    )
                )
            else:
                changes += compare_params(old_op, op, path, method)
                ns = op.get("summary") or op.get("operationId") or ""
                os_ = old_op.get("summary") or old_op.get("operationId") or ""
                if ns != os_:
                    changes.append(
                        Change(
                            kind="operation",
                            path=path,
                            method=method,
                            detail="summary changed",
                            summary=f"{_method_label(method)} {path} — summary changed",
                            breaking=False,
                            severity="info",
                            auxiliary={"old": os_, "new": ns},
                        )
                    )

    for path, item in old_paths.items():
        for method in _HTTP_METHODS:
            if isinstance(item, dict) and method in item:
                if path not in new_paths or method not in (
                    new_paths.get(path) or {}
                ):
                    changes.append(
                        Change(
                            kind="endpoint",
                            path=path,
                            method=method,
                            detail="endpoint removed",
                            summary=f"{_method_label(method)} {path} — endpoint removed",
                            breaking=True,
                            severity="high",
                        )
                    )

    changes += compare_schemas(old, new)
    return changes


_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def infer_semver(old_version: str, new_version: str, changes: list[Change]) -> dict:
    """Suggest a version bump based on changes (semver-style)."""
    breaking = any(c.breaking for c in changes)
    added_nonbreaking = any(
        not c.breaking and c.kind in ("endpoint", "parameter", "schema")
        for c in changes
    )
    has_any = any(
        c.kind in ("endpoint", "parameter", "schema", "operation") for c in changes
    )
    suggestion = "patch"
    if breaking:
        suggestion = "major"
    elif added_nonbreaking:
        suggestion = "minor"

    return {
        "from": old_version,
        "to": new_version,
        "breaking_changes": breaking,
        "changes_count": len(changes),
        "suggested_bump": suggestion,
    }


# -------------------------------------------------------------------------
# convenience API for CLI / action
# -------------------------------------------------------------------------


def diff_spec_text(old_text: str, new_text: str) -> tuple[list[dict], dict]:
    """High-level: parse two raw spec texts; return (change_dicts, semver)."""
    old = load_spec(old_text, "old")
    new = load_spec(new_text, "new")
    changes = compare_specs(old, new)
    semver = infer_semver(old.version_string, new.version_string, changes)
    return [c.to_dict() for c in changes], semver
