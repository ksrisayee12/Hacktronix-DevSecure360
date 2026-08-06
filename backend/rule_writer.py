import os
import yaml

RULES_DIR = os.path.join(os.path.dirname(__file__), "app", "scanner", "sast", "rules")

class LiteralString(str):
    pass

def literal_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

yaml.add_representer(LiteralString, literal_presenter)

def write_rule(lang, rule_id, vuln_class, severity, cwe, owasp, cvss_score, cvss_vector, confidence, issue, message, sources, sinks, sanitizers, remediation, evidence=None):
    rule = {
        "rule_id": rule_id,
        "language": lang,
        "vuln_class": vuln_class,
        "severity": severity,
        "cwe": cwe,
        "owasp": owasp,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "confidence": confidence,
        "issue": issue,
        "message": LiteralString(message.strip()),
        "sources": sources,
        "sinks": sinks,
        "sanitizers": sanitizers,
        "remediation": LiteralString(remediation.strip())
    }
    
    path = os.path.join(RULES_DIR, lang, f"{rule_id}.yaml")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        if evidence:
            f.write(evidence.strip() + "\n\n")
        yaml.dump(rule, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=float("inf"))
