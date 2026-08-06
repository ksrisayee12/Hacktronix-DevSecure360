from app.shared.types import Finding
from app.utils.ai_client import generate_completion

class RemediationEngine:
    """
    AI-Assisted Remediation Engine using local Ollama.
    """
    
    @staticmethod
    def generate_fix(finding: Finding, file_content: str = None) -> str:
        """
        Generates a customized fix for a given vulnerability finding using the AI provider.
        """
        prompt = (
            f"VULNERABILITY CONTEXT:\n"
            f"Issue: {finding.issue}\n"
            f"Description: {finding.description}\n"
            f"CWE: {finding.cwe}\n"
        )
        
        if finding.taint_trace:
            prompt += "\nTaint Trace (Data flow):\n"
            for t in finding.taint_trace:
                step = t.get("step") if isinstance(t, dict) else getattr(t, "step", "")
                line = t.get("line") if isinstance(t, dict) else getattr(t, "line", "")
                desc = t.get("description") if isinstance(t, dict) else getattr(t, "description", "")
                prompt += f"- Step {step} (Line {line}): {desc}\n"
                
        prompt += f"\nRemediation guidance: {finding.remediation}\n\n"
        
        if file_content:
            prompt += f"VULNERABLE CODE:\n```python\n{file_content}\n```\n\n"
        elif finding.evidence:
            prompt += f"VULNERABLE CODE:\n```python\n{finding.evidence}\n```\n\n"
            
        prompt += (
            "# INSTRUCTION: Rewrite the 'VULNERABLE CODE' above to fix the vulnerabilities. "
            "Output ONLY the complete, raw patched code snippet inside a SINGLE markdown block. Do NOT explain anything."
        )
        
        response = generate_completion(prompt)
        
        if not response:
            return "Failed to generate AI remediation. Check if Ollama is running and accessible."
            
        return response.strip()
