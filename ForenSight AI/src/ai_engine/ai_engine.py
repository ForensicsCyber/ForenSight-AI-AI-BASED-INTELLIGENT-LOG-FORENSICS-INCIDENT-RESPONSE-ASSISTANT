"""
ForenSight AI - AI Engine Controller
====================================

Central orchestration layer for AI-assisted
security analysis capabilities.

Responsibilities
----------------
1. Generate AI-driven attack summaries
2. Produce remediation recommendations
3. Coordinate LLM interactions
4. Normalize detection input structures

AI Components
-------------
• AISummarizer
• RecommendationEngine

Architecture Notes
------------------
• Supports local Ollama LLM execution
• Compatible with GUI and reporting layers
• Designed for lightweight SOC enrichment
"""

from src.ai_engine.summarizer import AISummarizer
from src.ai_engine.recommendations import RecommendationEngine

from src.utils.logger_config import setup_logger


# ---------------------------------------------------------
# LOGGER INITIALIZATION
# ---------------------------------------------------------

logger = setup_logger()


# ---------------------------------------------------------
# MAIN AI ENGINE
# ---------------------------------------------------------

def run_ai_engine(detection_results):
    """
    Execute AI-assisted security analysis.

    Parameters
    ----------
    detection_results : list or dict
        Detection alerts or aggregated results

    Returns
    -------
    dict
        AI-generated summary and recommendations
    """

    # ---------------------------------------------------------
    # Normalize Detection Input
    # ---------------------------------------------------------

    if isinstance(detection_results, dict):

        alerts = detection_results.get("alerts", [])

    else:

        alerts = detection_results

    # ---------------------------------------------------------
    # AI Summary Generation
    # ---------------------------------------------------------

    summarizer = AISummarizer()

    result = summarizer.summarize(alerts)

    summary = (

        result.get("ai_summary")

        or result.get("summary_text")

    )

    # ---------------------------------------------------------
    # Recommendation Generation
    # ---------------------------------------------------------

    recommendation_engine = RecommendationEngine()

    recommendations = recommendation_engine.generate(alerts)

    # ---------------------------------------------------------
    # Return AI Analysis
    # ---------------------------------------------------------

    return {

        "summary": summary,

        "recommendations": recommendations

    }