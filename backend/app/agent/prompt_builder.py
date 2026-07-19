# backend/app/agent/prompt_builder.py

import json
import os


def load_normalized_findings(normalized_path):
    """Load normalized findings JSON file."""
    with open(normalized_path, 'r', encoding='utf-8') as f:
        findings = json.load(f)
    return findings


def read_code_file(file_path):
    """Read the code lines from the provided file path."""
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    return lines


def build_prompt(finding, code_lines):
    """Construct an LLM prompt for a single finding using the full file code."""
    # Use full file as context so the LLM can return the complete updated file
    context = "".join(code_lines)

    prompt = (
        "Analyze the following code extract and its vulnerability:\n\n"
        f"File: {finding['file_path']}\n"
        f"Lines: {finding['start_line']} to {finding['end_line']}\n\n"
        f"Vulnerability Description: {finding['snippet']}\n\n"
        "Full File Code:\n"
        f"{context}\n"
        "TASK:\n"
        "- Confirm if the vulnerability exists at the mentioned location.\n"
        "- Compare the entire file's logic with and without the vulnerability.\n"
        "- Update the code to remove the vulnerability while preserving the logic of the file.\n"
        "- After modification, ensure the main code logic still works and the vulnerability is removed.\n"
        "- Do NOT introduce new features or change other logic. Only resolve the specified vulnerability.\n"
        "- CRITICAL: Respond with ONLY the full, updated contents of the Python file as valid code.\n"
        "- ABSOLUTELY NO markdown code fences (``````python), or triple quotes (''').\n"
        "- NO explanations, wrappers, or additional text BEFORE or AFTER the code.\n"
        "- At the VERY END of the file ONLY, append this exact Python comment block:\n"
        "  # AGENT FIX SUMMARY:\n"
        "  # Vulnerability fixed: [brief description]\n"
        "  # Changes made: [brief changes]\n"
        "  # Logic preserved: [why original logic works]\n"
        "- Your response must be parseable Python code from line 1 to final comment."
    )

    return prompt



def generate_prompts(normalized_findings_path, output_dir):
    """Generate LLM prompts for all findings and save them to files."""
    findings = load_normalized_findings(normalized_findings_path)
    prompts = []
    for idx, finding in enumerate(findings):
        if not os.path.exists(finding['file_path']):
            continue
        code_lines = read_code_file(finding['file_path'])
        prompt = build_prompt(finding, code_lines)
        output_file = os.path.join(output_dir, f"prompt_{idx+1}.txt")
        with open(output_file, 'w', encoding='utf-8') as pf:
            pf.write(prompt)
        prompts.append(output_file)
    return prompts


if __name__ == "__main__":
    # Update these paths as needed
    normalized_path = os.path.join(os.path.dirname(__file__), "normalized_findings.json")
    output_dir = os.path.join(os.path.dirname(__file__), "prompts")
    os.makedirs(output_dir, exist_ok=True)
    generated_prompts = generate_prompts(normalized_path, output_dir)
    print(f"Generated prompts: {generated_prompts}")
