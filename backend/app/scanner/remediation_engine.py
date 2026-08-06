from app.shared.types import Finding
from app.utils.ai_client import generate_completion

class RemediationEngine:
    """
    AI-Assisted Remediation Engine using local Ollama.
    """
    
    @staticmethod
    def generate_fix(findings: list[Finding], file_content: str = None) -> str:
        """
        Generates a customized fix for a list of vulnerability findings in a single file.
        """
        prompt = "VULNERABILITIES TO FIX:\n\n"
        for i, finding in enumerate(findings, 1):
            prompt += (
                f"--- Finding {i} ---\n"
                f"Issue: {finding.issue}\n"
                f"Description: {finding.description}\n"
                f"CWE: {finding.cwe}\n"
            )
            
            if finding.taint_trace:
                prompt += "Taint Trace (Data flow):\n"
                for t in finding.taint_trace:
                    step = t.get("step") if isinstance(t, dict) else getattr(t, "step", "")
                    line = t.get("line") if isinstance(t, dict) else getattr(t, "line", "")
                    desc = t.get("description") if isinstance(t, dict) else getattr(t, "description", "")
                    prompt += f"- Step {step} (Line {line}): {desc}\n"
                    
            prompt += f"Remediation guidance: {finding.remediation}\n\n"
            
        if file_content:
            prompt += f"VULNERABLE CODE:\n```python\n{file_content}\n```\n\n"
        elif findings and findings[0].evidence:
            prompt += f"VULNERABLE CODE:\n```python\n{findings[0].evidence}\n```\n\n"
            
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
