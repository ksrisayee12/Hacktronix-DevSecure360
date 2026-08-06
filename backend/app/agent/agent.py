# backend/app/agent/agent.py

import os
import json

from app.agent.normalizer import normalize_scan_history
from app.agent.prompt_builder import generate_prompts
from app.agent.ollama_llm_client import run_agent_on_prompts


def run_normalizer(scan_history_path: str, normalized_path: str) -> bool:
    """Run normalizer and write normalized findings JSON. Return True if any findings."""
    print("[1/3] Running normalizer...")
    normalized_findings = normalize_scan_history(scan_history_path)

    if not normalized_findings:
        print("No findings found in scan history. Stopping pipeline.")
        return False

    # Write normalized findings to file
    with open(normalized_path, "w", encoding="utf-8") as f:
        json.dump(normalized_findings, f, indent=2)
    print(f"Normalized findings saved to {normalized_path}")
    return True


def run_prompt_builder(normalized_path: str, prompts_dir: str) -> bool:
    """Run prompt builder and generate prompt_*.txt files. Return True if prompts created."""
    print("[2/3] Running prompt builder...")
    os.makedirs(prompts_dir, exist_ok=True)

    prompt_files = generate_prompts(normalized_path, prompts_dir)

    if not prompt_files:
        print("No prompts generated (no valid findings/files). Stopping pipeline.")
        return False

    print(f"Generated {len(prompt_files)} prompts in {prompts_dir}")
    return True


def run_ollama_patcher(prompts_dir: str) -> bool:
    """Run Ollama LLM client to process prompts and patch files."""
    print("[3/3] Running Ollama patcher...")
    run_agent_on_prompts(prompts_dir)
    print("Ollama patching step completed.")
    return True


def main():
    base_dir = os.path.dirname(__file__)

    # Paths
    scan_history_path = os.path.join(base_dir, "../database/scan_history.json")
    normalized_path = os.path.join(base_dir, "normalized_findings.json")
    prompts_dir = os.path.join(base_dir, "prompts")

    try:
        # Step 1: Normalize scan history
        if not run_normalizer(scan_history_path, normalized_path):
            return

        # Step 2: Build prompts from normalized findings
        if not run_prompt_builder(normalized_path, prompts_dir):
            return

        # Step 3: Send prompts to Ollama and patch code files
        run_ollama_patcher(prompts_dir)

        print("\nAgent pipeline completed successfully ✅")
    except Exception as e:
        print(f"\nAgent pipeline failed with error: {e}")


if __name__ == "__main__":
    main()
