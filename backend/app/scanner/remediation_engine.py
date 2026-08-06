from app.shared.types import Finding
from app.utils.ai_client import generate_completion

class RemediationEngine:
    """
    AI-Assisted Remediation Engine using local Ollama.
    """

    @staticmethod
    def generate_fix(findings, file_content: str = None) -> str:
        """
        Generates a customized fix for a list of vulnerability findings or a single finding in a file.
        Accepts a single Finding, a list of Findings, a dict, or a list of dicts.
        """
        if not findings:
            return "No findings provided for remediation."

        if not isinstance(findings, list):
            findings = [findings]

        prompt = "VULNERABILITIES TO FIX:\n\n"
        for i, f in enumerate(findings, 1):
            issue = f.get("issue") if isinstance(f, dict) else getattr(f, "issue", "")
            desc = f.get("description") if isinstance(f, dict) else getattr(f, "description", "")
            cwe = f.get("cwe") if isinstance(f, dict) else getattr(f, "cwe", "")
            remediation = f.get("remediation") if isinstance(f, dict) else getattr(f, "remediation", "")
            evidence = f.get("evidence") if isinstance(f, dict) else getattr(f, "evidence", "")
            taint = f.get("taint_trace") if isinstance(f, dict) else getattr(f, "taint_trace", [])

            prompt += (
                f"--- Finding {i} ---\n"
                f"Issue: {issue}\n"
                f"Description: {desc}\n"
                f"CWE: {cwe}\n"
            )

            if taint:
                prompt += "Taint Trace (Data flow):\n"
                for t in taint:
                    step = t.get("step") if isinstance(t, dict) else getattr(t, "step", "")
                    line = t.get("line") if isinstance(t, dict) else getattr(t, "line", "")
                    tdesc = t.get("description") if isinstance(t, dict) else getattr(t, "description", "")
                    prompt += f"- Step {step} (Line {line}): {tdesc}\n"

            prompt += f"Remediation guidance: {remediation}\n\n"

        first_evidence = (findings[0].get("evidence") if isinstance(findings[0], dict) else getattr(findings[0], "evidence", "")) if findings else ""

        if file_content:
            prompt += f"VULNERABLE CODE:\n```python\n{file_content}\n```\n\n"
        elif first_evidence:
            prompt += f"VULNERABLE CODE:\n```python\n{first_evidence}\n```\n\n"

        final_prompt = (
            "### Instruction:\n"
            "You are an expert security engineer. You must FIX the vulnerabilities listed below by rewriting the source code.\n"
            "YOU MUST MODIFY THE CODE TO REMOVE THE VULNERABILITY. Returning the original code is a failure.\n\n"
            f"{prompt}\n"
            "Output ONLY the complete, raw patched code snippet inside a SINGLE markdown block. Do NOT explain anything.\n\n"
            "### Response:\n"
            "```python\n"
        )

        response = generate_completion(final_prompt)

        if not response:
            return "Failed to generate AI remediation. Check if Ollama is running and accessible."

        return response.strip()
