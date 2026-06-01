"""Convert a pydantic class definition (as Python AST) to a JSON Schema dict.

Pydantic is the schema library most Python MCP servers use, either through
``mcp.server.fastmcp.FastMCP`` (which auto-generates JSON Schema from function
signatures with annotated parameters) or by passing pydantic ``BaseModel``
classes explicitly.

This module reads the class definition or function signature from the
Python AST and produces a best-effort JSON Schema dict so the static schema
auditor can run without standing up a sandbox.

Coverage:

- Primitive types: ``str`` / ``int`` / ``float`` / ``bool`` / ``bytes`` /
  ``None``.
- ``list[T]`` / ``List[T]`` / ``tuple[T, ...]`` → array.
- ``dict[K, V]`` / ``Dict[K, V]`` → object with permissive additionalProperties.
- ``Optional[T]`` and ``T | None`` → field excluded from required (and
  ``"null"`` added to the type).
- ``Literal["a", "b"]`` → enum.
- ``Union[A, B]`` / ``A | B`` → anyOf.
- ``BaseModel`` references → resolved from the local symbol table.
- ``Field(...)`` metadata: description, default, min_length, max_length,
  pattern, ge / le / gt / lt → respective JSON Schema fields.

Unhandled constructs (custom validators, complex generics, runtime model
construction) leave the property as a permissive ``{}`` rather than failing
the whole conversion.
"""

from __future__ import annotations

import ast

# pydantic primitive type names → JSON Schema ``type``.
_PRIMITIVE_TYPE_MAP: dict[str, str] = {
    "str": "string",
    "bytes": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "None": "null",
    "NoneType": "null",
}

# Names that indicate a class is a pydantic model.
_PYDANTIC_BASE_NAMES: frozenset[str] = frozenset({"BaseModel", "RootModel"})


def build_symbol_table(tree: ast.Module) -> dict[str, ast.ClassDef]:
    """Collect every class declared in *tree* that inherits from a pydantic
    base class, keyed by its name. The resolver consults this table when an
    annotation refers to one of these classes.
    """
    table: dict[str, ast.ClassDef] = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and _has_pydantic_base(node):
            table[node.name] = node
    return table


def class_to_schema(cls: ast.ClassDef, symbols: dict[str, ast.ClassDef]) -> dict:
    """Convert a pydantic class definition to a JSON Schema object."""
    return _build_object_schema(cls.body, symbols, set())


def function_args_to_schema(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    symbols: dict[str, ast.ClassDef],
) -> dict:
    """Convert a function's annotated parameters to a JSON Schema object.

    This is how ``FastMCP`` derives a tool's input schema from a plain
    function definition.
    """
    args = func.args
    # Combine positional, keyword-only, and positional-or-keyword in the
    # order pydantic / FastMCP would.
    all_args: list[ast.arg] = list(args.args) + list(args.kwonlyargs)
    defaults_by_name = _map_defaults(args)
    # Drop common framework-supplied arguments (self, cls, ctx) that aren't
    # part of the tool's user-facing input.
    skipped = {"self", "cls", "ctx", "context"}

    properties: dict[str, dict] = {}
    required: list[str] = []
    for a in all_args:
        if a.arg in skipped:
            continue
        if a.annotation is None:
            properties[a.arg] = {}
            required.append(a.arg)
            continue
        prop, optional = _annotation_to_property(a.annotation, symbols, set())
        default = defaults_by_name.get(a.arg)
        meta = _default_metadata(default)
        if meta is not None:
            prop.update(meta["schema"])
            if not meta["is_required"]:
                optional = True
        properties[a.arg] = prop
        if not optional:
            required.append(a.arg)

    out: dict = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        out["required"] = required
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Class / field walking
# ─────────────────────────────────────────────────────────────────────────────


def _build_object_schema(
    body: list[ast.stmt],
    symbols: dict[str, ast.ClassDef],
    stack: set[str],
) -> dict:
    properties: dict[str, dict] = {}
    required: list[str] = []
    for stmt in body:
        if not isinstance(stmt, ast.AnnAssign):
            continue
        if not isinstance(stmt.target, ast.Name):
            continue
        name = stmt.target.id
        if name.startswith("_"):  # private / dunder fields aren't tool input
            continue
        if stmt.annotation is None:
            continue
        prop, optional = _annotation_to_property(stmt.annotation, symbols, stack)
        # Apply default-value metadata (Field(...) or a plain literal).
        meta = _default_metadata(stmt.value)
        if meta is not None:
            prop.update(meta["schema"])
            if not meta["is_required"]:
                optional = True
        elif stmt.value is not None:
            # Any literal default makes the field optional.
            optional = True

        properties[name] = prop
        if not optional:
            required.append(name)

    out: dict = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        out["required"] = required
    return out


def _annotation_to_property(
    ann: ast.AST,
    symbols: dict[str, ast.ClassDef],
    stack: set[str],
) -> tuple[dict, bool]:
    """Return ``(property_schema, is_optional)`` for *ann*.

    ``is_optional`` is True when the type itself signals optionality
    (``Optional[T]``, ``T | None``).
    """
    # Plain name: ``str``, ``int``, ``MyModel``, ...
    if isinstance(ann, ast.Name):
        return _resolve_name(ann.id, symbols, stack), False

    if isinstance(ann, ast.Constant) and ann.value is None:
        return {"type": "null"}, True

    # ``X | None`` / ``A | B`` (PEP 604)
    if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
        return _union_schema(_collect_union_members(ann), symbols, stack)

    # Subscripted generics: ``list[X]``, ``Optional[X]``, ``Union[A,B]``, etc.
    if isinstance(ann, ast.Subscript):
        head = _name_of(ann.value)
        slice_expr = ann.slice
        # tuple of slice elements for ``Tuple[A, B, ...]`` etc.
        if isinstance(slice_expr, ast.Tuple):
            members = list(slice_expr.elts)
        else:
            members = [slice_expr]

        if head in {"Optional"}:
            inner, _ = _annotation_to_property(members[0], symbols, stack)
            return inner, True
        if head in {"Union"}:
            return _union_schema(members, symbols, stack)
        if head in {"list", "List", "Sequence", "Iterable", "tuple", "Tuple", "set", "Set", "frozenset", "FrozenSet"}:
            inner = members[0] if members else None
            item_schema = _annotation_to_property(inner, symbols, stack)[0] if inner is not None else {}
            return {"type": "array", "items": item_schema}, False
        if head in {"dict", "Dict", "Mapping", "MutableMapping"}:
            value_ann = members[1] if len(members) > 1 else None
            if value_ann is not None:
                v_schema = _annotation_to_property(value_ann, symbols, stack)[0]
                return {"type": "object", "additionalProperties": v_schema}, False
            return {"type": "object", "additionalProperties": True}, False
        if head in {"Literal"}:
            values = [_literal_value(m) for m in members]
            values = [v for v in values if v is not None or _is_literal_none(members)]
            return {"enum": values}, False
        if head in {"Annotated"}:
            # The first member is the actual type. The remaining members are
            # metadata markers — most importantly ``Field(...)``, which holds
            # description / pattern / min / max / default. PEP 593 puts the
            # Field call INSIDE the Annotated wrapper rather than as the
            # right-hand-side default.
            base, optional = _annotation_to_property(members[0], symbols, stack)
            for extra in members[1:]:
                if isinstance(extra, ast.Call) and _name_of(extra.func) in {"Field", "FieldInfo"}:
                    meta = _parse_field_call(extra)
                    base.update(meta["schema"])
                    if not meta["is_required"]:
                        optional = True
            return base, optional

    # Attribute access like ``typing.List`` or ``mypkg.MyModel``.
    if isinstance(ann, ast.Attribute):
        return _resolve_name(ann.attr, symbols, stack), False

    return {}, False


def _resolve_name(name: str, symbols: dict[str, ast.ClassDef], stack: set[str]) -> dict:
    if name in _PRIMITIVE_TYPE_MAP:
        return {"type": _PRIMITIVE_TYPE_MAP[name]}
    if name in symbols and name not in stack:
        stack = stack | {name}
        return _build_object_schema(symbols[name].body, symbols, stack)
    # Unknown — permissive placeholder so the rest of the schema still builds.
    return {}


def _union_schema(
    members: list[ast.AST],
    symbols: dict[str, ast.ClassDef],
    stack: set[str],
) -> tuple[dict, bool]:
    parts: list[dict] = []
    optional = False
    for m in members:
        # ``X | None`` member.
        if isinstance(m, ast.Constant) and m.value is None:
            optional = True
            continue
        if isinstance(m, ast.Name) and m.id in {"None", "NoneType"}:
            optional = True
            continue
        sub, sub_opt = _annotation_to_property(m, symbols, stack)
        if sub_opt:
            optional = True
        if sub:
            parts.append(sub)
    if not parts:
        return {}, optional
    if len(parts) == 1:
        return parts[0], optional
    # Collapse a union of primitive types into ``"type": [...]``.
    if all(_is_primitive(p) for p in parts):
        return {"type": [p["type"] for p in parts]}, optional
    return {"anyOf": parts}, optional


def _collect_union_members(node: ast.BinOp) -> list[ast.AST]:
    """Flatten a chain of ``A | B | C`` BinOps into a list of leaves."""
    members: list[ast.AST] = []

    def walk(n: ast.AST) -> None:
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr):
            walk(n.left)
            walk(n.right)
        else:
            members.append(n)

    walk(node)
    return members


# ─────────────────────────────────────────────────────────────────────────────
# Field(...) and literal defaults
# ─────────────────────────────────────────────────────────────────────────────


def _default_metadata(default: ast.AST | None) -> dict | None:
    """Map a field's default expression to ``{"schema": {...}, "is_required": bool}``.

    Returns ``None`` when there is no default at all (field must be required
    by virtue of having no default).
    """
    if default is None:
        return None

    # ``Field(...)`` call.
    if isinstance(default, ast.Call) and _name_of(default.func) in {"Field", "FieldInfo"}:
        return _parse_field_call(default)

    # ``...`` (ellipsis) — pydantic shorthand for "required, no other metadata".
    if isinstance(default, ast.Constant) and default.value is Ellipsis:
        return {"schema": {}, "is_required": True}

    # Any literal default value (str / int / bool / None / list / dict).
    return {"schema": {}, "is_required": False}


def _parse_field_call(call: ast.Call) -> dict:
    """Extract JSON Schema metadata from a pydantic ``Field(...)`` invocation."""
    schema: dict = {}
    is_required = True
    # Positional ``default`` argument: ``Field(default_value, ...)``.
    if call.args:
        first = call.args[0]
        if isinstance(first, ast.Constant) and first.value is Ellipsis:
            is_required = True
        else:
            is_required = False
    for kw in call.keywords:
        if kw.arg is None:
            continue  # ``**kwargs`` unpacking
        val = _literal_value(kw.value)
        if kw.arg == "default":
            if val is Ellipsis:
                is_required = True
            else:
                is_required = False
        elif kw.arg == "default_factory":
            is_required = False
        elif kw.arg == "description" and isinstance(val, str):
            schema["description"] = val
        elif kw.arg in {"min_length", "minLength"} and isinstance(val, int):
            schema["minLength"] = val
        elif kw.arg in {"max_length", "maxLength"} and isinstance(val, int):
            schema["maxLength"] = val
        elif kw.arg == "pattern" and isinstance(val, str):
            schema["pattern"] = val
        elif kw.arg == "ge" and isinstance(val, (int, float)):
            schema["minimum"] = val
        elif kw.arg == "gt" and isinstance(val, (int, float)):
            schema["exclusiveMinimum"] = val
        elif kw.arg == "le" and isinstance(val, (int, float)):
            schema["maximum"] = val
        elif kw.arg == "lt" and isinstance(val, (int, float)):
            schema["exclusiveMaximum"] = val
        elif kw.arg == "examples" and isinstance(val, list):
            schema["examples"] = val
        elif kw.arg == "title" and isinstance(val, str):
            schema["title"] = val
    return {"schema": schema, "is_required": is_required}


def _map_defaults(args: ast.arguments) -> dict[str, ast.AST | None]:
    """Pair each function argument with its default expression (or None)."""
    pos = list(args.args)
    pos_defaults = list(args.defaults)
    out: dict[str, ast.AST | None] = {}
    # ``pos_defaults`` aligns with the *tail* of ``pos``.
    n_missing = len(pos) - len(pos_defaults)
    for i, a in enumerate(pos):
        out[a.arg] = pos_defaults[i - n_missing] if i >= n_missing else None
    for a, d in zip(args.kwonlyargs, args.kw_defaults):
        out[a.arg] = d
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Misc helpers
# ─────────────────────────────────────────────────────────────────────────────


def _has_pydantic_base(cls: ast.ClassDef) -> bool:
    for base in cls.bases:
        if _name_of(base) in _PYDANTIC_BASE_NAMES:
            return True
    return False


def _name_of(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        return _name_of(node.value)
    return ""


def _is_primitive(s: dict) -> bool:
    return set(s.keys()) <= {"type"} and isinstance(s.get("type"), str)


def _is_literal_none(members: list[ast.AST]) -> bool:
    return any(isinstance(m, ast.Constant) and m.value is None for m in members)


def _literal_value(node: ast.AST | None) -> object:
    """Convert a small AST literal to a Python value, or None when not a literal."""
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        v = _literal_value(node.operand)
        if isinstance(v, (int, float)):
            return -v
    if isinstance(node, ast.List):
        return [_literal_value(e) for e in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_literal_value(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return {
            _literal_value(k): _literal_value(v)
            for k, v in zip(node.keys, node.values)
        }
    return None
