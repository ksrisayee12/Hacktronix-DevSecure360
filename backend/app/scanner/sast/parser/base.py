# backend/app/scanner/sast/parser/base.py
"""
Tree-sitter initialization for all supported languages.
Provides parse_file(), get_node_text(), walk_tree() utilities.

tree-sitter 0.26.x + tree-sitter-language-pack API:
    from tree_sitter_language_pack import get_language, get_parser
    language = get_language('python')         # returns Language object
    parser   = get_parser('python')           # returns pre-configured Parser
    tree     = parser.parse(bytes_source)

All node APIs (start_byte, end_byte, start_point, child_by_field_name, etc.)
are identical to 0.21.x — only the Language/Parser initialization changed.

Supported languages (Phase 1):
    Python, JavaScript/TypeScript, Java, PHP, C, C++, Go, C#
"""

from tree_sitter import Language, Parser

# ── Language initialization via tree-sitter-language-pack ─────────────────────
# This single package bundles all grammars. No per-language packages needed.

try:
    from tree_sitter_language_pack import (
        get_language as _get_language,
        get_parser   as _get_parser,
    )
    _LANGUAGE_PACK_AVAILABLE = True
except ImportError:
    _LANGUAGE_PACK_AVAILABLE = False
    print("[parser/base] WARNING: tree-sitter-language-pack not installed. "
          "Run: pip install tree-sitter-language-pack")


def _load_language(name: str) -> Language | None:
    """
    Load a Language from tree-sitter-language-pack.
    Returns None gracefully if the language or pack is unavailable.
    """
    if not _LANGUAGE_PACK_AVAILABLE:
        return None
    try:
        return _get_language(name)
    except Exception as e:
        print(f"[parser/base] WARNING: {name} grammar not available: {e}")
        return None


def _load_parser(name: str) -> Parser | None:
    """
    Load a ready-to-use Parser from tree-sitter-language-pack.
    Returns None gracefully if unavailable.
    """
    if not _LANGUAGE_PACK_AVAILABLE:
        return None
    try:
        return _get_parser(name)
    except Exception as e:
        print(f"[parser/base] WARNING: {name} parser not available: {e}")
        return None


import tree_sitter_go
import tree_sitter_c_sharp

# ── Language objects ───────────────────────────────────────────────────────────
PY_LANGUAGE   = _load_language("python")
JS_LANGUAGE   = _load_language("javascript")
TS_LANGUAGE   = _load_language("typescript")
JAVA_LANGUAGE = _load_language("java")
PHP_LANGUAGE  = _load_language("php")
C_LANGUAGE    = _load_language("c")
CPP_LANGUAGE  = _load_language("cpp")
GO_LANGUAGE   = Language(tree_sitter_go.language())
CSHARP_LANGUAGE = Language(tree_sitter_c_sharp.language())

# ── Pre-built parsers (one per language for reuse) ────────────────────────────
_PY_PARSER   = _load_parser("python")
_JS_PARSER   = _load_parser("javascript")
_TS_PARSER   = _load_parser("typescript")
_JAVA_PARSER = _load_parser("java")
_PHP_PARSER  = _load_parser("php")
_C_PARSER    = _load_parser("c")
_CPP_PARSER  = _load_parser("cpp")

_GO_PARSER = Parser(GO_LANGUAGE)
_CSHARP_PARSER = Parser(CSHARP_LANGUAGE)


# ── Extension → (Language, Parser) mapping ────────────────────────────────────
LANGUAGE_MAP: dict[str, Language]  = {}
_PARSER_MAP:  dict[str, Parser]    = {}

def _register(ext: str, lang: Language | None, parser: Parser | None):
    if lang and parser:
        LANGUAGE_MAP[ext] = lang
        _PARSER_MAP[ext]  = parser

_register(".py",   PY_LANGUAGE,   _PY_PARSER)
_register(".js",   JS_LANGUAGE,   _JS_PARSER)
_register(".ts",   TS_LANGUAGE,   _TS_PARSER)
_register(".jsx",  JS_LANGUAGE,   _JS_PARSER)
_register(".tsx",  TS_LANGUAGE,   _TS_PARSER)
_register(".java", JAVA_LANGUAGE, _JAVA_PARSER)
_register(".php",  PHP_LANGUAGE,  _PHP_PARSER)
_register(".c",    C_LANGUAGE,    _C_PARSER)
_register(".h",    C_LANGUAGE,    _C_PARSER)
_register(".cpp",  CPP_LANGUAGE,  _CPP_PARSER)
_register(".cc",   CPP_LANGUAGE,  _CPP_PARSER)
_register(".cxx",  CPP_LANGUAGE,  _CPP_PARSER)
_register(".hpp",  CPP_LANGUAGE,  _CPP_PARSER)
_register(".go",   GO_LANGUAGE,   _GO_PARSER)
_register(".cs",   CSHARP_LANGUAGE, _CSHARP_PARSER)

# ── Public API ─────────────────────────────────────────────────────────────────

def get_parser(extension: str) -> Parser | None:
    """Return a configured Parser for the given file extension, or None if unsupported."""
    return _PARSER_MAP.get(extension.lower())


def parse_file(source_code: str, extension: str):
    """
    Parse source code string into a tree-sitter tree.
    Returns (tree, parser) or (None, None) if unsupported extension or parse error.
    """
    parser = get_parser(extension)
    if not parser:
        return None, None
    try:
        tree = parser.parse(bytes(source_code, "utf-8"))
        return tree, parser
    except Exception as e:
        print(f"[parser/base] Parse error for {extension}: {e}")
        return None, None


def get_node_text(node, source_bytes: bytes) -> str:
    """Extract the exact text a node covers in the source."""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def walk_tree(node):
    """Generator that yields every node in the tree via depth-first traversal."""
    yield node
    for child in node.children:
        yield from walk_tree(child)


def is_language_supported(extension: str) -> bool:
    """Check if a file extension has a parser available."""
    return extension.lower() in LANGUAGE_MAP


def supported_extensions() -> list[str]:
    """Return all currently supported file extensions."""
    return list(LANGUAGE_MAP.keys())
