"""Extract MCP tool definitions (name + description + input schema) from
a source tree.

Heuristic, regex- and zod-aware. Operates on the directory carried by the
environment snapshot — either a local source checkout or an extracted
remote tarball. The output feeds the static description scanner (R3) and
the schema auditor (R5) so both can run without standing up a sandbox.

For each tool, the extractor attempts three pieces:

- Name and description: regex pair matching, accepting plain object literals,
  ``z.literal(...)`` wrappers, JSON-style keys, and Python keyword form.
- Input schema: when the source is JS/TS, the matched name/description is
  followed up with a search for the same object's ``arguments`` /
  ``inputSchema`` / ``parameters`` / ``schema`` field, whose value (a zod
  expression) is converted to a JSON Schema dict via
  ``zod_to_schema.convert``.

Limitations:

- Schema recovery covers common zod shapes (object/string/number/boolean/
  array/literal/enum, plus ``.optional``/``.describe``/``.min``/``.max``/
  ``.regex``/``.email``/``.url``/``.extend``). Refinements, custom
  transforms, or runtime-built schemas are not represented; the tool gets
  ``input_schema = None`` in that case and the schema auditor falls back to
  the runtime ``tools/list`` for that tool.
- Pydantic models are parsed via ``pydantic_to_schema`` for FastMCP-style
  ``@tool()`` decorated functions and ``Tool(...)`` constructor calls; SDKs
  that build schemas through other patterns (custom validators, runtime
  composition) fall back to runtime input.
- Heuristic. May miss tools whose definition is built at runtime, or pick
  up spurious matches; the identifier guard filters most noise.

When this extractor returns an empty list (no source tree, or no
recognisable definitions found), the findings runner falls back to the
runtime ``tools/list`` for description scanning.
"""

from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path

from mcp_security_analyzer.dynamic.models import ToolInfo
from mcp_security_analyzer.static.pydantic_to_schema import (
    build_symbol_table as py_build_symbol_table,
    class_to_schema as py_class_to_schema,
    function_args_to_schema as py_function_args_to_schema,
)
from mcp_security_analyzer.static.zod_to_schema import (
    build_symbol_table as zod_build_symbol_table,
    convert as zod_convert,
)

# Limits matching the source analyzer so we don't walk huge trees.
_SCAN_FILE_LIMIT = 500
_SCAN_BYTES_LIMIT = 256 * 1024
_SCAN_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs",
    ".ts", ".tsx", ".mts", ".cts", ".json",
}
_SCAN_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "__pycache__",
    "node_modules", "dist-info", ".next", ".turbo", ".cache",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
}

# MCP tool names are flat identifiers by convention.
_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")

# Reserved field names that show up next to ``description:`` strings in
# package manifests / config objects but are not tool names.
_NON_TOOL_NAMES = {
    "name", "description", "main", "module", "type", "license",
    "author", "version", "homepage", "repository",
}

# Markers that, if present together inside a JSON object, identify it as a
# package manifest rather than a tool definition. Two or more required.
_MANIFEST_MARKERS = {
    "version", "dependencies", "devDependencies", "peerDependencies",
    "scripts", "bin", "files", "engines", "main", "module",
}
_MANIFEST_MARKER_THRESHOLD = 2

# Maximum distance (in characters) between a ``name`` literal and its
# associated ``description`` literal in source text. Keeps the regex from
# pairing unrelated fields.
_PAIR_WINDOW = 400

# Pair a name literal with a description literal within a short distance.
# Accepts the common shapes seen in real MCP servers:
#   - Plain JS/TS object: ``name: "x"`` ... ``description: "y"``
#   - zod schema:         ``name: z.literal("x")`` ... ``description: z.literal("y")``
#   - Python keyword:     ``name="x"`` ... ``description="y"``
#   - JSON-style keys:    ``"name": "x"`` ... ``"description": "y"``
# Both ``name`` and ``description`` may independently be wrapped in
# ``z.literal(...)``. Quoted strings may use ``"``, ``'``, or backticks.
_PAIR_PATTERNS = (
    re.compile(
        r'["\']?name["\']?\s*[:=]\s*(?:z\.literal\(\s*)?'
        r'["\'`](?P<name>[^"\'`]{1,128})["\'`]\s*\)?'
        r'(?P<gap>.{0,' + str(_PAIR_WINDOW) + r'}?)'
        r'["\']?description["\']?\s*[:=]\s*(?:z\.literal\(\s*)?'
        r'(?P<quote>["\'`])(?P<desc>(?:\\.|(?!(?P=quote)).){1,2000})(?P=quote)\s*\)?',
        re.DOTALL,
    ),
)


def extract_tools_from_source(root: Path) -> list[ToolInfo]:
    """Walk *root*, extract tool definitions, return ``ToolInfo``s.

    Each ``ToolInfo`` carries ``name`` + ``description`` + (when recoverable)
    an ``input_schema`` derived from the JS/TS zod expression.

    Returns an empty list when *root* is not a directory or nothing
    recognisable was found.
    """
    if not root.is_dir():
        return []

    # name → (description, input_schema). First match wins.
    seen: dict[str, tuple[str, dict | None]] = {}
    scanned = 0
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIRS]
        for name in files:
            path = Path(current) / name
            if path.suffix.lower() not in _SCAN_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > _SCAN_BYTES_LIMIT:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            suffix = path.suffix.lower()
            if suffix == ".json":
                # JSON parses structurally (with manifest filtering); running
                # the text regex on it would re-introduce package.json's own
                # name + description as a phantom tool.
                _collect_from_json(text, seen)
            elif suffix in (".py", ".pyi"):
                # Python sources use AST walking — schemas come from pydantic
                # ``BaseModel`` classes or annotated function parameters.
                _collect_from_python(text, seen)
            else:
                _collect_from_text(text, seen)

            scanned += 1
            if scanned >= _SCAN_FILE_LIMIT:
                break
        if scanned >= _SCAN_FILE_LIMIT:
            break

    return [
        ToolInfo(name=n, description=d, input_schema=schema)
        for n, (d, schema) in seen.items()
    ]


# ─────────────────────────────────────────────────────────────────────────────
# JSON collector
# ─────────────────────────────────────────────────────────────────────────────


def _collect_from_json(text: str, seen: dict[str, tuple[str, dict | None]]) -> None:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return
    _walk_json(data, seen)


def _walk_json(node: object, seen: dict[str, tuple[str, dict | None]]) -> None:
    if isinstance(node, dict):
        if _looks_like_manifest_object(node):
            return  # do not descend; skip the whole manifest object
        name = node.get("name")
        desc = node.get("description")
        if isinstance(name, str) and isinstance(desc, str):
            if not _looks_non_tool(name) and desc.strip():
                # If a JSON object also declares an inputSchema (e.g. the
                # MCP tools/list response shape leaked into a file), pass it
                # through.
                schema = node.get("inputSchema") or node.get("input_schema")
                schema = schema if isinstance(schema, dict) else None
                seen.setdefault(name, (desc, schema))
        for v in node.values():
            _walk_json(v, seen)
    elif isinstance(node, list):
        for item in node:
            _walk_json(item, seen)


def _looks_like_manifest_object(obj: dict) -> bool:
    keys = set(obj.keys())
    return sum(1 for m in _MANIFEST_MARKERS if m in keys) >= _MANIFEST_MARKER_THRESHOLD


# ─────────────────────────────────────────────────────────────────────────────
# Text (JS/TS/Python) collector
# ─────────────────────────────────────────────────────────────────────────────


def _collect_from_text(
    text: str,
    seen: dict[str, tuple[str, dict | None]],
) -> None:
    # Build the zod symbol table once for this file so cross-tool references
    # (e.g. ``arguments: ElementSchema.extend({...})``) can resolve.
    symbols = zod_build_symbol_table(text)
    for rx in _PAIR_PATTERNS:
        for m in rx.finditer(text):
            name = m.group("name")
            desc = m.group("desc")
            if not name or not desc:
                continue
            if _looks_non_tool(name):
                continue
            desc = _unescape_basic(desc).strip()
            if not desc:
                continue
            schema = _extract_input_schema(text, m.end(), symbols)
            seen.setdefault(name, (desc, schema))


def _extract_input_schema(
    text: str,
    description_end: int,
    symbols: dict[str, str],
) -> dict | None:
    """Search forward from *description_end* for the tool's schema field and
    convert its zod expression to a JSON Schema dict.

    Looks for any of ``arguments``, ``inputSchema``, ``input_schema``,
    ``parameters``, ``schema`` within a short window — these are the field
    names real MCP servers use to declare a tool's input shape.
    """
    window = text[description_end : description_end + _SCHEMA_SEARCH_WINDOW]
    m = _SCHEMA_KEY_RE.search(window)
    if not m:
        return None
    expr_start = description_end + m.end()
    expr_text = _take_expression(text, expr_start)
    if not expr_text:
        return None
    try:
        return zod_convert(expr_text, symbols)
    except Exception:  # noqa: BLE001 — conversion is best-effort
        return None


def _take_expression(text: str, start: int) -> str:
    """Read a JS expression starting at *start* until a depth-0 ``,`` or
    ``}`` ends it. Skips over balanced parens/braces/brackets and strings.
    """
    i = start
    n = len(text)
    depth = 0
    while i < n:
        ch = text[i]
        if ch in ("\"", "'", "`"):
            quote = ch
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                i += 1
            i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            break
        i += 1
    return text[start:i].strip()


# Field names a tool declaration may use for its input schema.
_SCHEMA_KEY_RE = re.compile(
    r'(?:["\']?(?:arguments|inputSchema|input_schema|parameters|schema)["\']?\s*[:=]\s*)'
)
_SCHEMA_SEARCH_WINDOW = 600


def _unescape_basic(s: str) -> str:
    # Decode a small set of common backslash escapes without invoking the
    # full source language's lexer.
    return (
        s.replace("\\n", "\n")
         .replace("\\t", "\t")
         .replace('\\"', '"')
         .replace("\\'", "'")
         .replace("\\\\", "\\")
    )


# ─────────────────────────────────────────────────────────────────────────────
# Identifier guard
# ─────────────────────────────────────────────────────────────────────────────


def _looks_non_tool(name: str) -> bool:
    # Reject prose titles ("Browser MCP"), npm package specs ("@scope/pkg"),
    # URLs, paths — common noise from inlined package.json blocks and config
    # objects. MCP tool names are flat identifiers by convention.
    if not name or not _TOOL_NAME_RE.match(name):
        return True
    if name.lower() in _NON_TOOL_NAMES:
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Python (AST) collector
# ─────────────────────────────────────────────────────────────────────────────


# Decorator names that mark a function as an MCP tool. Both the attribute form
# (``@mcp.tool()``, ``@server.tool``) and the bare form (``@tool()``) are
# accepted. Any callable on a module attribute whose final name is ``tool`` is
# treated as a tool decorator.
_TOOL_DECORATOR_NAMES: frozenset[str] = frozenset({"tool", "register_tool"})

# Constructor calls that wrap a tool definition. ``mcp.types.Tool``,
# ``types.Tool``, or just ``Tool`` — keyed by the final identifier in the
# call's attribute chain.
_TOOL_CONSTRUCTOR_NAMES: frozenset[str] = frozenset({"Tool"})


def _collect_from_python(
    text: str,
    seen: dict[str, tuple[str, dict | None]],
) -> None:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return

    symbols = py_build_symbol_table(tree)
    enums = _build_enum_table(tree)

    for node in ast.walk(tree):
        # FastMCP-style decorated function: tool name = function name,
        # description = docstring, schema = function args.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not _is_tool_decorated(node):
                continue
            name = node.name
            if _looks_non_tool(name):
                continue
            desc = ast.get_docstring(node) or ""
            if not desc:
                continue
            schema = py_function_args_to_schema(node, symbols)
            seen.setdefault(name, (desc.strip(), schema))
            continue

        # Low-level ``Tool(name=..., description=..., inputSchema=...)``
        # construction. Also recognises ``types.Tool(...)`` etc.
        if isinstance(node, ast.Call) and _is_tool_constructor(node):
            details = _parse_tool_constructor_call(node, symbols, enums)
            if details is None:
                continue
            name, desc, schema = details
            if _looks_non_tool(name):
                continue
            seen.setdefault(name, (desc, schema))


def _is_tool_decorated(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for deco in func.decorator_list:
        target = deco.func if isinstance(deco, ast.Call) else deco
        last = _final_attr_name(target)
        if last in _TOOL_DECORATOR_NAMES:
            return True
    return False


def _is_tool_constructor(call: ast.Call) -> bool:
    return _final_attr_name(call.func) in _TOOL_CONSTRUCTOR_NAMES


def _parse_tool_constructor_call(
    call: ast.Call,
    symbols: dict,
    enums: dict[tuple[str, str], object],
) -> tuple[str, str, dict | None] | None:
    name: str | None = None
    desc: str | None = None
    schema: dict | None = None
    for kw in call.keywords:
        if kw.arg is None:
            continue
        if kw.arg == "name":
            v = _resolve_string_expr(kw.value, enums)
            if isinstance(v, str):
                name = v
        elif kw.arg == "description":
            v = _resolve_string_expr(kw.value, enums)
            if isinstance(v, str):
                desc = v
        elif kw.arg in {"inputSchema", "input_schema"}:
            schema = _resolve_schema_expr(kw.value, symbols)
    if name is None or desc is None:
        return None
    return name, desc.strip(), schema


def _resolve_string_expr(
    node: ast.AST,
    enums: dict[tuple[str, str], object],
) -> str | None:
    """Resolve a string-valued expression: literal, or ``EnumClass.MEMBER`` /
    ``EnumClass.MEMBER.value`` references whose backing value is a string.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    # ``EnumClass.MEMBER.value`` — Attribute('.value') over Attribute(MEMBER)
    if isinstance(node, ast.Attribute) and node.attr == "value":
        inner = node.value
        if isinstance(inner, ast.Attribute) and isinstance(inner.value, ast.Name):
            v = enums.get((inner.value.id, inner.attr))
            if isinstance(v, str):
                return v
    # ``EnumClass.MEMBER`` (str-Enum mixin lets this be used as a string directly).
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        v = enums.get((node.value.id, node.attr))
        if isinstance(v, str):
            return v
    return None


def _resolve_schema_expr(node: ast.AST, symbols: dict) -> dict | None:
    """Resolve an ``inputSchema=`` value: literal dict, pydantic class
    reference, or a ``<ClassName>.model_json_schema()`` invocation.
    """
    if isinstance(node, ast.Dict):
        return _ast_dict_to_python(node)
    if isinstance(node, ast.Name) and node.id in symbols:
        return py_class_to_schema(symbols[node.id], symbols)
    # ``<Name>.model_json_schema()`` — pydantic v2's built-in JSON Schema
    # exporter. Reconstruct the same schema from our static parser.
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"model_json_schema", "schema"}:
            head = node.func.value
            if isinstance(head, ast.Name) and head.id in symbols:
                return py_class_to_schema(symbols[head.id], symbols)
    return None


def _build_enum_table(tree: ast.Module) -> dict[tuple[str, str], object]:
    """Map ``(EnumClassName, member)`` → literal value for ``str``/``int``
    Enum subclasses defined at module level.

    Recognises the common shapes ``class X(str, Enum)`` and
    ``class X(int, Enum)`` whose members are assigned literal values.
    """
    out: dict[tuple[str, str], object] = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = {_final_attr_name(b) for b in node.bases}
        if "Enum" not in base_names and "IntEnum" not in base_names and "StrEnum" not in base_names:
            continue
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
                    continue
                member = stmt.targets[0].id
                if isinstance(stmt.value, ast.Constant):
                    out[(node.name, member)] = stmt.value.value
    return out


def _final_attr_name(node: ast.AST) -> str:
    """Return the rightmost identifier of a name or attribute chain."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _ast_dict_to_python(node: ast.Dict) -> dict | None:
    """Recursively convert an ast.Dict of literals to a Python dict."""
    out: dict = {}
    for k, v in zip(node.keys, node.values):
        if not isinstance(k, ast.Constant) or not isinstance(k.value, str):
            return None
        out[k.value] = _ast_value_to_python(v)
    return out


def _ast_value_to_python(node: ast.AST) -> object:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Dict):
        return _ast_dict_to_python(node)
    if isinstance(node, ast.List):
        return [_ast_value_to_python(e) for e in node.elts]
    if isinstance(node, ast.Tuple):
        return [_ast_value_to_python(e) for e in node.elts]
    return None
