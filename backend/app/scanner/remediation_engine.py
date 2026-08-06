from app.shared.types import Finding
from app.utils.ai_client import generate_completion

class RemediationEngine:
    """
    AI-Assisted Remediation Engine using local Ollama.
    """
    
    @staticmethod
    def generate_fix(finding: Finding) -> str:
        """
        Generates a customized fix for a given vulnerability finding using the AI provider.
        """
        # Construct the prompt based on the finding details
        prompt = (
            f"You are an expert DevSecOps engineer. Fix the following {finding.vuln_class} vulnerability.\n\n"
            f"Issue: {finding.issue}\n"
            f"Description: {finding.description}\n"
            f"CWE: {finding.cwe}\n"
        )
        
        if finding.evidence:
            prompt += f"\nVulnerable Code snippet:\n```\n{finding.evidence}\n```\n"
            
        if finding.taint_trace:
            prompt += "\nTaint Trace (Data flow):\n"
            for t in finding.taint_trace:
                # Need to handle dictionary vs object depending on how it's stored
                step = t.get("step") if isinstance(t, dict) else getattr(t, "step", "")
                line = t.get("line") if isinstance(t, dict) else getattr(t, "line", "")
                desc = t.get("description") if isinstance(t, dict) else getattr(t, "description", "")
                prompt += f"- Step {step} (Line {line}): {desc}\n"
                
        prompt += (
            f"\nRemediation guidance: {finding.remediation}\n\n"
            "Provide the patched code snippet that directly replaces the vulnerable evidence. "
            "Return ONLY the raw code inside a single markdown code block (```). Do not include any explanations, introductory text, or concluding remarks. "
            "Ensure the fix directly addresses the vulnerability using secure best practices."
        )
        
        response = generate_completion(prompt)
        
        if not response:
            return "Failed to generate AI remediation. Check if Ollama is running and accessible."
            
        return response.strip()
