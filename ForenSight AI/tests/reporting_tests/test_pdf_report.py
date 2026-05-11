import sys
import os

# Add project root to Python path
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from src.detection.detection_engine import run_detection_engine
from src.ai_engine.ai_engine import run_ai_engine
from src.reporting.report_builder import build_report_content
from src.reporting.pdf_generator import generate_pdf_report


def test_report():

    detection_results = run_detection_engine()

    ai_results = run_ai_engine(detection_results)

    report_data = build_report_content(
        detection_results,
        ai_results
    )

    generate_pdf_report(report_data, "forensight_report.pdf")

    print("Report Generated Successfully!")


if __name__ == "__main__":
    test_report()