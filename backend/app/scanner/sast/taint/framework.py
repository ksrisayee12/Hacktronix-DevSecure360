# backend/app/scanner/sast/taint/framework.py
"""
Framework Detection and Source Modeling.

Automatically detects which web framework a file uses (Flask, Django, FastAPI, Express, Spring)
and loads the appropriate source definitions.

This is critical because:
    Flask:   request.args.get("x")   → source
    Django:  request.GET["x"]        → source (different API!)
    FastAPI: def endpoint(name: str) → the parameter ITSELF is the source
    Express: req.query.name          → source (JavaScript)
    Spring:  @RequestParam String x  → the parameter is the source (Java)
"""

import re
from dataclasses import dataclass, field

# ── Framework Source Definitions ──────────────────────────────────────────────

FRAMEWORK_SOURCES: dict[str, list[str]] = {
    "flask": [
        "request.args.get", "request.args[",
        "request.form.get", "request.form[",
        "request.json", "request.get_json",
        "request.values.get", "request.values[",
        "request.data", "request.files",
        "request.cookies.get", "request.cookies[",
        "request.headers.get", "request.headers[",
        "request.environ.get",
    ],
    "django": [
        "request.GET.get", "request.GET[",
        "request.POST.get", "request.POST[",
        "request.data", "request.query_params",
        "request.body", "request.FILES",
        "request.META.get", "request.META[",
        "request.COOKIES.get", "request.COOKIES[",
        "request.resolver_match",
        "self.kwargs.get",
    ],
    "fastapi": [
        # FastAPI uses typed parameters — the param name itself is the source
        # These are detected structurally (function param with no default or Body())
        "Request.query_params", "Request.headers",
        "Request.cookies", "Request.body",
        "request.query_params", "request.headers.get",
    ],
    "aiohttp": [
        "request.rel_url.query", "request.query",
        "request.match_info", "request.json",
        "request.post", "request.headers",
        "request.cookies",
    ],
    "tornado": [
        "self.get_argument", "self.get_query_argument",
        "self.get_body_argument", "self.request.arguments",
        "self.request.body", "self.request.headers",
    ],
    "express_js": [
        "req.query", "req.params", "req.body",
        "req.headers", "req.cookies",
        "request.query", "request.params", "request.body",
    ],
    "spring_java": [
        # Spring MVC — @RequestParam parameters are sources
        "@RequestParam", "request.getParameter",
        "request.getHeader", "request.getAttribute",
        "httpRequest.getParameter", "servletRequest.getParameter",
    ],
    "generic": [
        # Generic sources valid for any framework
        "input(", "sys.argv", "os.environ.get", "os.getenv",
        "os.environ[", "argv[", "getenv(",
        # CLI args
        "argparse", "click.argument", "click.option",
        # Any HTTP library input
        "urllib.parse.parse_qs", "cgi.FieldStorage",
    ],
}

# ── Framework Detection ───────────────────────────────────────────────────────

@dataclass
class DetectedFramework:
    name: str
    confidence: float       # 0.0 to 1.0
    sources: list[str]      # all source patterns for this framework


def detect_framework(source_code: str, language: str = "python") -> DetectedFramework:
    """
    Detect the web framework used in a source file.
    
    Uses import/require statement analysis and usage pattern matching.
    Returns a DetectedFramework with the appropriate source list.
    """
    code_lower = source_code.lower()
    scores: dict[str, float] = {}

    if language == "python":
        scores = _detect_python_framework(source_code, code_lower)
    elif language in ("javascript", "typescript"):
        scores = _detect_js_framework(source_code, code_lower)
    elif language == "java":
        scores = _detect_java_framework(source_code, code_lower)

    # Always include generic sources
    sources = list(FRAMEWORK_SOURCES["generic"])

    if not scores:
        return DetectedFramework(name="generic", confidence=0.5, sources=sources)

    best_framework = max(scores, key=lambda k: scores[k])
    confidence = min(scores[best_framework], 1.0)

    # Merge framework-specific sources with generic
    framework_sources = FRAMEWORK_SOURCES.get(best_framework, [])
    sources = list(set(sources + framework_sources))

    return DetectedFramework(
        name=best_framework,
        confidence=confidence,
        sources=sources
    )


def _detect_python_framework(source_code: str, code_lower: str) -> dict[str, float]:
    scores = {}

    # Flask detection
    flask_signals = [
        (r"from flask import", 0.8),
        (r"import flask", 0.6),
        (r"flask\.Flask\(", 0.9),
        (r"@app\.route\(", 0.9),
        (r"request\.args", 0.7),
    ]
    flask_score = sum(w for pat, w in flask_signals if re.search(pat, code_lower))
    if flask_score > 0:
        scores["flask"] = flask_score

    # Django detection
    django_signals = [
        (r"from django", 0.9),
        (r"import django", 0.7),
        (r"django\.http", 0.8),
        (r"request\.get\b", 0.5),
        (r"urlpatterns", 0.8),
    ]
    django_score = sum(w for pat, w in django_signals if re.search(pat, code_lower))
    if django_score > 0:
        scores["django"] = django_score

    # FastAPI detection
    fastapi_signals = [
        (r"from fastapi import", 0.9),
        (r"import fastapi", 0.7),
        (r"fastapi\.fastapi\(", 0.9),
        (r"@app\.(get|post|put|delete)\(", 0.8),
    ]
    fastapi_score = sum(w for pat, w in fastapi_signals if re.search(pat, code_lower))
    if fastapi_score > 0:
        scores["fastapi"] = fastapi_score

    # Tornado detection
    tornado_signals = [
        (r"import tornado", 0.9),
        (r"tornado\.web", 0.8),
        (r"self\.get_argument\(", 0.9),
    ]
    tornado_score = sum(w for pat, w in tornado_signals if re.search(pat, code_lower))
    if tornado_score > 0:
        scores["tornado"] = tornado_score

    # aiohttp detection
    aiohttp_signals = [
        (r"import aiohttp", 0.9),
        (r"from aiohttp", 0.8),
        (r"aiohttp\.web", 0.9),
    ]
    aiohttp_score = sum(w for pat, w in aiohttp_signals if re.search(pat, code_lower))
    if aiohttp_score > 0:
        scores["aiohttp"] = aiohttp_score

    return scores


def _detect_js_framework(source_code: str, code_lower: str) -> dict[str, float]:
    scores = {}

    express_signals = [
        (r"require\(['\"]express", 0.9),
        (r"from ['\"]express", 0.8),
        (r"express\(\)", 0.8),
        (r"req\.query\.", 0.7),
        (r"req\.body\.", 0.7),
        (r"app\.(get|post|put|delete)\(", 0.7),
    ]
    express_score = sum(w for pat, w in express_signals if re.search(pat, code_lower))
    if express_score > 0:
        scores["express_js"] = express_score

    return scores


def _detect_java_framework(source_code: str, code_lower: str) -> dict[str, float]:
    scores = {}

    spring_signals = [
        (r"import org\.springframework", 0.9),
        (r"@restcontroller", 0.9),
        (r"@requestmapping", 0.8),
        (r"@requestparam", 0.8),
        (r"httpservletrequest", 0.7),
    ]
    spring_score = sum(w for pat, w in spring_signals if re.search(pat, code_lower))
    if spring_score > 0:
        scores["spring_java"] = spring_score

    return scores


def get_framework_augmented_rules(rules: dict, framework: DetectedFramework) -> dict:
    """
    Return a copy of the rules dict with framework-specific sources merged in.
    This ensures taint analysis uses the full source list for the detected framework.
    """
    import copy
    augmented = copy.deepcopy(rules)

    for rule_id, rule in augmented.items():
        existing_sources = rule.get("sources", [])
        # Merge framework sources into this rule's source list
        merged = list(set(existing_sources + framework.sources))
        rule["sources"] = merged

    return augmented
