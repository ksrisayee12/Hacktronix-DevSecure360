import os
import yaml
from pathlib import Path

RULES_DIR = Path(__file__).parent.absolute()

def load_rules(language: str) -> dict:
    rules = {}
    lang_dir = RULES_DIR / language
    if not lang_dir.exists() or not lang_dir.is_dir():
        return rules
    
    for yaml_file in lang_dir.glob("*.yaml"):
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                rule_dict = yaml.safe_load(f)
                if rule_dict and "rule_id" in rule_dict:
                    rules[rule_dict["rule_id"]] = rule_dict
        except Exception as e:
            print(f"Error loading rule {yaml_file}: {e}")
    return rules

def load_all_rules() -> dict:
    all_rules = {}
    for lang_dir in RULES_DIR.iterdir():
        if lang_dir.is_dir():
            all_rules.update(load_rules(lang_dir.name))
    return all_rules
