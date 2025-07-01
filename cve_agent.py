import json
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class CVEReport:
    description: str
    technical_details: str
    cvss_score: float
    epss_score: float
    vendor_statements: List[str]
    third_party_analysis: List[str]
    exploitation_status: str
    validation_flags: List[str]

@dataclass
class Assessment:
    legitimacy_status: str
    priority_level: str
    confidence: str
    action_required: str
    technical_validation: str
    evidence_quality: str
    recommendations: str

class CVEAnalyst:
    def analyze(self, report: CVEReport) -> Assessment:
        legitimacy, priority = self._determine_legitimacy_priority(report)
        confidence = self._determine_confidence(report)
        action = self._determine_action(priority)

        technical_validation = self._technical_validation(report)
        evidence_quality = self._evidence_quality(report)
        recommendations = self._recommendations(priority)

        return Assessment(
            legitimacy_status=legitimacy,
            priority_level=priority,
            confidence=confidence,
            action_required=action,
            technical_validation=technical_validation,
            evidence_quality=evidence_quality,
            recommendations=recommendations,
        )

    def _determine_legitimacy_priority(self, report: CVEReport):
        if report.cvss_score >= 7 and report.epss_score >= 0.5:
            return "LEGITIMATE", "HIGH"
        if report.cvss_score >= 7:
            return "LEGITIMATE", "MEDIUM"
        if report.epss_score >= 0.5:
            return "LEGITIMATE", "MEDIUM"
        return "INSUFFICIENT_DATA", "LOW"

    def _determine_confidence(self, report: CVEReport):
        if "VALIDATION_MISMATCH" in report.validation_flags:
            return "MEDIUM"
        if report.vendor_statements and report.third_party_analysis:
            return "HIGH"
        return "LOW"

    def _determine_action(self, priority: str):
        if priority == "HIGH":
            return "IMMEDIATE"
        if priority == "MEDIUM":
            return "SCHEDULED"
        return "MONITOR"

    def _technical_validation(self, report: CVEReport):
        return (
            f"CVSS {report.cvss_score}, EPSS {report.epss_score}. "
            f"Details: {report.technical_details}"
        )

    def _evidence_quality(self, report: CVEReport):
        sources = len(report.vendor_statements) + len(report.third_party_analysis)
        flags = ", ".join(report.validation_flags) if report.validation_flags else "None"
        return f"Sources: {sources}; Validation Flags: {flags}"

    def _recommendations(self, priority: str):
        if priority == "HIGH":
            return "Apply patches immediately and monitor exploitation attempts."
        if priority == "MEDIUM":
            return "Schedule patching and monitor advisories."
        return "Gather more data before action."


def load_report(path: str) -> CVEReport:
    with open(path, 'r') as fh:
        data = json.load(fh)
    return CVEReport(**data)


def main(path: str):
    report = load_report(path)
    analyst = CVEAnalyst()
    assessment = analyst.analyze(report)
    print(json.dumps(assessment.__dict__, indent=2))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Analyze CVE reports")
    parser.add_argument("report", help="Path to CVE report JSON file")
    args = parser.parse_args()
    main(args.report)
