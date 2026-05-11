"""
ForenSight AI - Prompt Builder
==============================

Constructs structured prompts for AI-assisted
security analysis.

Responsibilities
----------------
1. Generate AI summary prompts
2. Generate remediation prompts
3. Standardize LLM instructions
4. Normalize detection input formatting

Architecture Notes
------------------
• Optimized for local Ollama execution
• Lightweight prompt engineering layer
• Shared across AI modules
"""


# ---------------------------------------------------------
# SUMMARY PROMPT
# ---------------------------------------------------------

def build_summary_prompt(results):
    """
    Build AI summary prompt.

    Parameters
    ----------
    results : dict
        Detection analysis results

    Returns
    -------
    str
        Structured LLM prompt
    """

    return f"""
You are a professional cybersecurity analyst.

Analyze the following detection results.

Alerts:
{results.get("alerts", [])[:20]}

IOCs:
{results.get("iocs", {})}

Statistics:
{results.get("statistics", {})}

Tasks:
1. Explain detected attacks
2. Identify severity levels
3. Describe attacker behavior
4. Summarize overall threat posture

Output:
Provide a clear, professional,
SOC-style incident summary.
"""


# ---------------------------------------------------------
# RECOMMENDATION PROMPT
# ---------------------------------------------------------

def build_recommendation_prompt(results):
    """
    Build AI recommendation prompt.

    Parameters
    ----------
    results : dict
        Detection analysis results

    Returns
    -------
    str
        Structured LLM prompt
    """

    return f"""
You are a cybersecurity expert.

Based on the following detected attacks:

{results.get("alerts", [])[:20]}

Tasks:
1. Recommend mitigation steps
2. Suggest prevention strategies
3. Recommend security controls
4. Improve incident response readiness

Output:
Provide concise professional
bullet-point recommendations.
"""