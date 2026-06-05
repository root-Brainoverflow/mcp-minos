"""Convert a zod schema expression (as source text) to a JSON Schema dict.

zod is the most common JavaScript/TypeScript schema library used by MCP
servers (the official ``@modelcontextprotocol/sdk`` examples and most
community servers use it). This module reads the zod expression as written
in source code and produces a best-effort JSON Schema so the static schema
auditor can run without standing up a sandbox.

Coverage is intentionally narrow — the common shapes that real MCP servers
write:

- ``z.object({...})``  → object with properties / required
- ``z.string()``        → ``{"type": "string"}``
- ``z.number()`` / ``z.bigint()`` → ``{"type": "number"}``
- ``z.boolean()``       → ``{"type": "boolean"}``
- ``z.array(<inner>)``  → array with items
- ``z.literal(v)``      → ``{"const": v}``
- ``z.enum([...])``     → ``{"enum": [...]}``
- ``z.null()`` / ``z.undefined()`` → respective shape
- Symbol references (``ElementSchema``) → resolved from the symbol table.
- ``<Symbol>.extend({...})`` → fields of Symbol plus the extension body.

Modifiers (chained on any of the above):

- ``.optional()`` — field excluded from ``required``
- ``.nullable()`` — adds ``null`` to the type
- ``.describe("...")`` → ``description``
- ``.min(n)`` / ``.max(n)`` / ``.length(n)`` → length / numeric bounds
- ``.regex(...)`` → ``pattern`` (RegExp source extracted as text)
- ``.email()`` / ``.url()`` / ``.uuid()`` → ``format``
- ``.default(...)`` / ``.refine(...)`` / ``.transform(...)`` — ignored.

Unrecognised constructs return ``None`` for that subtree (and the auditor
treats it as untyped) rather than failing the whole conversion.
"""

from __future__ import annotations

import re

# Capture top-level ``var/let/const NAME = z.object({...})`` declarations.
_DECL_RE = re.compile(
    r"\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(z\.object\s*\()",
)

# A zod chain root we recognise.
_CHAIN_ROOT_RE = re.compile(
    r"^(z\.(?:object|string|number|bigint|boolean|array|literal|enum|null|undefined|union|tuple|record|map|set|date|any|unknown|never)|[A-Za-z_$][\w$]*)\s*"
)


def build_symbol_table(text: str) -> dict[str, str]:
    """Walk *text* and collect ``NAME → expression`` for every top-level zod
    declaration. The expression is captured as source text and parsed lazily.
    """
    table: dict[str, str] = {}
    for m in _DECL_RE.finditer(text):
        name = m.group(1)
        # The match consumed up to the opening ``(`` of ``z.object(``. Find the
        # matching ``)`` and capture the whole expression including any
        # ``.extend(...)``-style chain that follows.
        open_paren = m.end() - 1
        close = _balance(text, open_paren, "(", ")")
        if close is None:
            continue
        end = _consume_chain_tail(text, close + 1)
        table[name] = text[m.end() - len("z.object("):end].strip()
    return table


def convert(expression: str, symbols: dict[str, str]) -> dict | None:
    """Convert a zod expression to a JSON Schema dict, or ``None`` if it
    can't be recognised.
    """
    return _parse_chain(expression.strip(), symbols, _SymbolStack())


# ─────────────────────────────────────────────────────────────────────────────
# Internal
# ─────────────────────────────────────────────────────────────────────────────


class _SymbolStack:
    """Cycle guard for symbol resolution."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def __contains__(self, name: str) -> bool:
        return name in self._seen

    def push(self, name: str) -> None:
        self._seen.add(name)

    def pop(self, name: str) -> None:
        self._seen.discard(name)


def _parse_chain(expr: str, symbols: dict[str, str], stack: _SymbolStack) -> dict | None:
    expr = expr.strip()
    m = _CHAIN_ROOT_RE.match(expr)
    if not m:
        return None

    head = m.group(1)
    rest = expr[m.end():]

    # Parse the root.
    if head.startswith("z."):
        kind = head.split(".", 1)[1]
        root_args, after = _take_call(rest)
        node = _build_root(kind, root_args, symbols, stack)
    else:
        # Symbol reference. Optional ``.extend(...)`` may follow.
        node = _resolve_symbol(head, symbols, stack)
        after = rest

    if node is None:
        return None

    # Walk any modifier chain (``.method(args).method(args)...``).
    while True:
        after = after.lstrip()
        if not after.startswith("."):
            break
        # Method name: identifier after the dot.
        mm = re.match(r"\.([A-Za-z_$][\w$]*)", after)
        if not mm:
            break
        method = mm.group(1)
        rest_after_name = after[mm.end():].lstrip()
        if not rest_after_name.startswith("("):
            # Method without parens, unusual. Skip the name and continue.
            after = rest_after_name
            continue
        call_args, after = _take_call(rest_after_name)
        _apply_modifier(node, method, call_args, symbols, stack)

    return node


def _build_root(
    kind: str,
    args: str,
    symbols: dict[str, str],
    stack: _SymbolStack,
) -> dict | None:
    if kind == "object":
        return _parse_object_body(args, symbols, stack)
    if kind == "string":
        return {"type": "string"}
    if kind in ("number", "bigint"):
        return {"type": "number"}
    if kind == "boolean":
        return {"type": "boolean"}
    if kind == "array":
        item = _parse_chain(args, symbols, stack) if args.strip() else None
        out: dict = {"type": "array"}
        if item is not None:
            out["items"] = item
        return out
    if kind == "literal":
        val = _parse_literal_value(args)
        return {"const": val} if val is not None else None
    if kind == "enum":
        # ``z.enum([...])`` — args is the bracketed list.
        items = _parse_array_of_literals(args)
        return {"enum": items} if items else None
    if kind in ("null", "undefined"):
        return {"type": "null"}
    if kind == "union":
        # Treat union of objects/types as anyOf. Best-effort.
        opts = []
        for part in _split_top_level(args, ","):
            sub = _parse_chain(part.strip(), symbols, stack)
            if sub is not None:
                opts.append(sub)
        return {"anyOf": opts} if opts else None
    if kind == "record":
        return {"type": "object", "additionalProperties": True}
    if kind in ("any", "unknown"):
        return {}  # no constraint — maximally permissive
    if kind == "date":
        return {"type": "string", "format": "date-time"}
    # tuple/map/set/never not handled.
    return None


def _resolve_symbol(name: str, symbols: dict[str, str], stack: _SymbolStack) -> dict | None:
    if name in stack:
        return None  # cycle
    expr = symbols.get(name)
    if expr is None:
        # Unknown symbol — return a permissive placeholder so callers can still
        # attach modifiers / extends without crashing.
        return {}
    stack.push(name)
    try:
        return _parse_chain(expr, symbols, stack)
    finally:
        stack.pop(name)


def _apply_modifier(
    node: dict,
    method: str,
    args: str,
    symbols: dict[str, str],
    stack: _SymbolStack,
) -> None:
    if method == "optional":
        node["_optional"] = True
    elif method == "nullable":
        # Convert ``type: X`` → ``type: [X, "null"]`` if a type is set.
        t = node.get("type")
        if isinstance(t, str):
            node["type"] = [t, "null"]
    elif method == "describe":
        val = _parse_literal_value(args)
        if isinstance(val, str):
            node["description"] = val
    elif method in ("min", "max", "length"):
        n = _parse_literal_value(args)
        if isinstance(n, (int, float)):
            t = node.get("type")
            target_min = "minLength" if t == "string" else "minimum"
            target_max = "maxLength" if t == "string" else "maximum"
            if method == "min":
                node[target_min] = n
            elif method == "max":
                node[target_max] = n
            else:  # length
                node[target_min] = n
                node[target_max] = n
    elif method == "regex":
        # First positional argument; may be `/pattern/flags` or `new RegExp(...)`.
        rx = _extract_regex_source(args)
        if rx:
            node["pattern"] = rx
    elif method in ("email", "url", "uuid"):
        node["format"] = {"email": "email", "url": "uri", "uuid": "uuid"}[method]
    elif method == "extend":
        # Symbol-based: parent already parsed; merge an inline object body.
        ext = _parse_object_body(args, symbols, stack)
        if ext and ext.get("type") == "object":
            base_props = node.setdefault("properties", {})
            base_props.update(ext.get("properties", {}))
            base_required = set(node.get("required", []))
            base_required.update(ext.get("required", []))
            node["required"] = sorted(base_required)
    # default/refine/transform/superRefine/brand/readonly: ignored.


# ─────────────────────────────────────────────────────────────────────────────
# Object body
# ─────────────────────────────────────────────────────────────────────────────


def _parse_object_body(body: str, symbols: dict[str, str], stack: _SymbolStack) -> dict:
    inner = _strip_outer_braces(body.strip()).strip()
    out: dict = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
    if not inner:
        return out
    for field in _split_top_level(inner, ","):
        field = field.strip()
        if not field:
            continue
        # ``name: <chain>`` or ``"name": <chain>``.
        m = re.match(r"\s*(?:\"([^\"]+)\"|'([^']+)'|([A-Za-z_$][\w$]*))\s*:\s*(.+)$", field, re.DOTALL)
        if not m:
            continue
        prop = m.group(1) or m.group(2) or m.group(3)
        chain = m.group(4).strip()
        parsed = _parse_chain(chain, symbols, stack)
        if parsed is None:
            continue
        optional = parsed.pop("_optional", False)
        out["properties"][prop] = parsed
        if not optional:
            out["required"].append(prop)
    if not out["required"]:
        out.pop("required")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Lexing helpers
# ─────────────────────────────────────────────────────────────────────────────


def _take_call(text: str) -> tuple[str, str]:
    """Given text starting with ``(``, return (inside, remainder_after_close)."""
    text = text.lstrip()
    if not text.startswith("("):
        return "", text
    end = _balance(text, 0, "(", ")")
    if end is None:
        return "", text
    return text[1:end], text[end + 1:]


def _consume_chain_tail(text: str, start: int) -> int:
    """From *start*, walk ``.method(args)`` chains and return the index after
    the last consumed character.
    """
    i = start
    n = len(text)
    while i < n and text[i] == ".":
        # Match identifier
        j = i + 1
        if j >= n or not (text[j].isalpha() or text[j] == "_" or text[j] == "$"):
            break
        while j < n and (text[j].isalnum() or text[j] in "_$"):
            j += 1
        # Allow whitespace between name and ``(``
        k = j
        while k < n and text[k].isspace():
            k += 1
        if k >= n or text[k] != "(":
            break
        close = _balance(text, k, "(", ")")
        if close is None:
            break
        i = close + 1
    return i


def _balance(text: str, open_at: int, open_ch: str, close_ch: str) -> int | None:
    """Find the index of the *close_ch* that matches *open_ch* at *open_at*,
    skipping over string literals (``"..."``, ``'...'``, backticks).
    """
    depth = 0
    i = open_at
    n = len(text)
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
        if ch == "/" and i + 1 < n and text[i + 1] in "/*":
            # Skip JS comments. // line, /* block */
            if text[i + 1] == "/":
                end = text.find("\n", i + 2)
                i = n if end == -1 else end + 1
            else:
                end = text.find("*/", i + 2)
                i = n if end == -1 else end + 2
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _split_top_level(text: str, delim: str) -> list[str]:
    """Split *text* by *delim* at depth 0 (outside parens/brackets/braces/strings)."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in ("\"", "'", "`"):
            quote = ch
            buf.append(ch)
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\" and i + 1 < n:
                    buf.append(text[i])
                    buf.append(text[i + 1])
                    i += 2
                    continue
                buf.append(text[i])
                i += 1
            if i < n:
                buf.append(text[i])
                i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == delim and depth == 0:
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def _strip_outer_braces(text: str) -> str:
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return text[1:-1]
    return text


# ─────────────────────────────────────────────────────────────────────────────
# Literal / array parsers
# ─────────────────────────────────────────────────────────────────────────────


def _parse_literal_value(text: str) -> object:
    """Best-effort: parse a JS literal expression to a Python value.
    Returns None when the expression isn't a recognised literal.
    """
    t = text.strip().rstrip(",").strip()
    if not t:
        return None
    # String
    if (t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'")):
        return _unescape_js_string(t[1:-1])
    if t.startswith("`") and t.endswith("`"):
        return _unescape_js_string(t[1:-1])
    # Number
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    if re.fullmatch(r"-?\d+\.\d+(?:[eE][-+]?\d+)?", t):
        return float(t)
    # Bool / null
    if t == "true":
        return True
    if t == "false":
        return False
    if t == "null":
        return None
    return None


def _parse_array_of_literals(text: str) -> list:
    t = text.strip()
    if t.startswith("[") and t.endswith("]"):
        inner = t[1:-1]
    else:
        inner = t
    out: list = []
    for part in _split_top_level(inner, ","):
        v = _parse_literal_value(part)
        if v is not None or part.strip() == "null":
            out.append(v)
    return out


def _unescape_js_string(s: str) -> str:
    return (
        s.replace("\\n", "\n")
         .replace("\\t", "\t")
         .replace('\\"', '"')
         .replace("\\'", "'")
         .replace("\\\\", "\\")
    )


def _extract_regex_source(args: str) -> str | None:
    t = args.strip()
    # /pattern/flags
    m = re.match(r"^/(.*)/[gimsuy]*\s*,?", t, re.DOTALL)
    if m:
        return m.group(1)
    # First positional string argument.
    first = _split_top_level(t, ",")[0].strip()
    if (first.startswith('"') and first.endswith('"')) or (first.startswith("'") and first.endswith("'")):
        return _unescape_js_string(first[1:-1])
    return None
