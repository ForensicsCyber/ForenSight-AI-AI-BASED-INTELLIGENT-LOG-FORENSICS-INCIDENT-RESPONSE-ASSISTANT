import sys
import os

# Add project root directory to Python path
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from src.detection.detection_engine import run_detection_engine
from src.ai_engine.ai_engine import run_ai_engine


def test_ai():

    detection_results = run_detection_engine()

    ai_results = run_ai_engine(detection_results)

    print("\n=== AI SUMMARY ===\n")
    print(ai_results["summary"])

    print("\n=== AI RECOMMENDATIONS ===\n")
    print(ai_results["recommendations"])


if __name__ == "__main__":
    test_ai()