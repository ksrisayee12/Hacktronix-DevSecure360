# backend/app/scanner/sast/rules/loader.py
"""
YAML rule file loader for the DevSecure360 SAST engine.

Loads all YAML rule files for a given language from:
    scanner/sast/rules/{language}/*.yaml

Returns a combined dict: {rule_id: rule_dict}
"""

import yaml
import os


def load_rules(language: str = "python") -> dict:
    """
    Load all YAML rule files for a given language.
    Returns a dict: {rule_id: rule_dict}

    Rule files live at: scanner/sast/rules/{language}/*.yaml
    """
    rules_dir = os.path.join(os.path.dirname(__file__), language)
    rules = {}

    if not os.path.exists(rules_dir):
        print(f"[rules/loader] No rules directory found for language: {language}")
        return rules

    for filename in sorted(os.listdir(rules_dir)):
        if not filename.endswith(".yaml") and not filename.endswith(".yml"):
            continue
        filepath = os.path.join(rules_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)
            if rule and "rule_id" in rule:
                rules[rule["rule_id"]] = rule
            else:
                print(f"[rules/loader] Warning: {filename} missing 'rule_id' field, skipping")
        except Exception as e:
            print(f"[rules/loader] Warning: failed to load {filepath}: {e}")

    return rules


def load_all_rules() -> dict[str, dict]:
    """
    Load rules for all supported languages.
    Returns: {"python": {...rules}, "javascript": {...rules}, ...}
    """
    languages = ["python", "javascript", "java", "php", "c", "cpp"]
    all_rules = {}
    for lang in languages:
        rules = load_rules(lang)
        if rules:
            all_rules[lang] = rules
    return all_rules
