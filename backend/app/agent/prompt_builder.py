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
        "You are an elite Secure Software Engineer, Senior Python Developer, Application Security Researcher, and Static Analysis Expert.\n\n"
        "Your responsibility is to patch exactly ONE reported security vulnerability while preserving the application's functionality.\n\n"
        "You are acting as an automated security patching agent.\n\n"
        "===========================================================\n"
        "MISSION\n"
        "===========================================================\n\n"
        "Your objective is to produce a secure version of the provided source file.\n\n"
        "The patch must:\n\n"
        "• Eliminate the reported vulnerability.\n"
        "• Preserve application behavior.\n"
        "• Preserve business logic.\n"
        "• Preserve APIs.\n"
        "• Preserve formatting whenever possible.\n"
        "• Introduce no new vulnerabilities.\n"
        "• Produce valid executable Python code.\n\n"
        "Your answer will directly overwrite the existing source file.\n\n"
        "Accuracy is more important than creativity.\n\n"
        "===========================================================\n"
        "VULNERABILITY DETAILS\n"
        "===========================================================\n\n"
        f"File:\n{finding.get('file_path', 'Unknown')}\n\n"
        "Language:\nPython\n\n"
        f"Affected Lines:\n{finding.get('start_line', 'N/A')} - {finding.get('end_line', 'N/A')}\n\n"
        f"Rule ID:\n{finding.get('rule_id', 'N/A')}\n\n"
        f"Scanner:\n{finding.get('tool', 'N/A')}\n\n"
        f"Severity:\n{finding.get('severity', 'N/A')}\n\n"
        f"Confidence:\n{finding.get('confidence', 'N/A')}\n\n"
        f"OWASP:\n{finding.get('owasp', 'N/A')}\n\n"
        f"CWE:\n{finding.get('cwe', 'N/A')}\n\n"
        f"Category:\n{finding.get('vuln_class', 'N/A')}\n\n"
        f"Vulnerability Name:\n{finding.get('issue', 'N/A')}\n\n"
        f"Description:\n\n{finding.get('snippet', 'N/A')}\n\n"
        f"Recommended Fix:\n\n{finding.get('remediation', 'N/A')}\n\n"
        "===========================================================\n"
        "SOURCE INFORMATION\n"
        "===========================================================\n\n"
        f"Potential Source:\n\n{finding.get('source', 'N/A')}\n\n"
        f"Potential Sink:\n\n{finding.get('sink', 'N/A')}\n\n"
        f"User Controlled Input:\n\n{finding.get('user_input', 'N/A')}\n\n"
        "===========================================================\n"
        "PATCH OBJECTIVES\n"
        "===========================================================\n\n"
        "Fix ONLY the vulnerability described above.\n\n"
        "Do NOT perform unrelated refactoring.\n\n"
        "Do NOT optimize the code.\n\n"
        "Do NOT rewrite unrelated functions.\n\n"
        "Do NOT rename variables unless absolutely necessary.\n\n"
        "Do NOT modify APIs.\n\n"
        "Do NOT change public interfaces.\n\n"
        "Do NOT alter return values.\n\n"
        "Do NOT remove logging unless insecure.\n\n"
        "Do NOT remove exception handling unless insecure.\n\n"
        "Keep all comments unless they expose sensitive information.\n\n"
        "===========================================================\n"
        "SECURE CODING REQUIREMENTS\n"
        "===========================================================\n\n"
        "Follow these principles:\n\n"
        "✔ Validate all untrusted input.\n\n"
        "✔ Sanitize user-controlled values.\n\n"
        "✔ Use allowlists over denylists.\n\n"
        "✔ Use parameterized database queries.\n\n"
        "✔ Never concatenate SQL.\n\n"
        "✔ Never execute user input as commands.\n\n"
        "✔ Avoid shell=True.\n\n"
        "✔ Prevent path traversal.\n\n"
        "✔ Prevent SSRF.\n\n"
        "✔ Prevent XSS.\n\n"
        "✔ Prevent insecure deserialization.\n\n"
        "✔ Avoid unsafe eval().\n\n"
        "✔ Use secure cryptographic APIs.\n\n"
        "✔ Remove hardcoded secrets.\n\n"
        "✔ Use constant-time comparison where appropriate.\n\n"
        "✔ Preserve authentication logic.\n\n"
        "✔ Preserve authorization checks.\n\n"
        "===========================================================\n"
        "PATCHING RULES\n"
        "===========================================================\n\n"
        "Only modify code necessary to fix the issue.\n\n"
        "Keep the patch as small as possible.\n\n"
        "Preserve whitespace where practical.\n\n"
        "Do not reorder imports.\n\n"
        "Do not change formatting unless required.\n\n"
        "Do not change unrelated comments.\n\n"
        "Do not add unnecessary helper functions.\n\n"
        "Do not create new files.\n\n"
        "Do not delete existing functions unless they are completely insecure.\n\n"
        "===========================================================\n"
        "IF THE REPORTED ISSUE IS INCORRECT\n"
        "===========================================================\n\n"
        "If the scanner produced a false positive:\n\n"
        "• Leave the code unchanged.\n\n"
        "Still return the ENTIRE source file.\n\n"
        "Never explain that it is a false positive.\n\n"
        "===========================================================\n"
        "INTERNAL REASONING\n"
        "===========================================================\n\n"
        "Before writing code, internally determine:\n\n"
        "1. Root cause.\n\n"
        "2. Data flow.\n\n"
        "3. Attack vector.\n\n"
        "4. Why the vulnerability exists.\n\n"
        "5. Best secure remediation.\n\n"
        "6. Possible regressions.\n\n"
        "7. Verify the fix.\n\n"
        "DO NOT OUTPUT THIS ANALYSIS.\n\n"
        "===========================================================\n"
        "FULL SOURCE FILE\n"
        "===========================================================\n\n"
        f"{context}\n\n"
        "===========================================================\n"
        "OUTPUT REQUIREMENTS\n"
        "===========================================================\n\n"
        "Return the COMPLETE Python file.\n\n"
        "Never return only the modified lines.\n\n"
        "Never truncate the file.\n\n"
        "Never omit unchanged code.\n\n"
        "The returned file must be directly writable over the original file.\n\n"
        "===========================================================\n"
        "STRICT OUTPUT FORMAT\n"
        "===========================================================\n\n"
        "Return ONLY valid Python code.\n\n"
        "DO NOT output:\n\n"
        "Markdown\n\n"
        "Triple backticks\n\n"
        "```python\n\n"
        "Explanations\n\n"
        "Bullet lists\n\n"
        "JSON\n\n"
        "XML\n\n"
        "HTML\n\n"
        "Natural language\n\n"
        "Notes\n\n"
        "Warnings\n\n"
        "Anything outside Python code\n\n"
        "===========================================================\n"
        "SELF VERIFICATION\n"
        "===========================================================\n\n"
        "Before finalizing, silently verify:\n\n"
        "✓ Vulnerability removed.\n\n"
        "✓ File is syntactically valid.\n\n"
        "✓ No imports are missing.\n\n"
        "✓ No functions were accidentally deleted.\n\n"
        "✓ Existing behavior remains.\n\n"
        "✓ No placeholder code exists.\n\n"
        "✓ No TODO comments were added.\n\n"
        "✓ No new vulnerabilities introduced.\n\n"
        "✓ Patch follows secure coding practices.\n\n"
        "If any verification fails, fix it before generating the final answer.\n\n"
        "===========================================================\n"
        "FINAL REQUIREMENT\n"
        "===========================================================\n\n"
        "Append the following comment block to the END of the Python file.\n\n"
        "# =========================================================\n"
        "# AGENT FIX SUMMARY\n"
        "# =========================================================\n"
        "# Vulnerability:\n"
        "# Severity:\n"
        "# CWE:\n"
        "# OWASP:\n"
        "# Root Cause:\n"
        "# Fix Applied:\n"
        "# Security Benefit:\n"
        "# Modified Functions:\n"
        "# Confidence:\n"
        "# =========================================================\n\n"
        "Populate every field.\n\n"
        "===========================================================\n"
        "REMEMBER\n"
        "===========================================================\n\n"
        "Your output will overwrite the existing source file.\n\n"
        "Return ONLY executable Python code.\n\n"
        "Return the COMPLETE file.\n\n"
        "Do not use Markdown.\n\n"
        "Do not include explanations.\n\n"
        "Do not include code fences.\n\n"
        "Output ONLY the patched Python source.\n"
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
