from typing import List, Dict, Any, Tuple

def calculate_risk(findings: List[Dict[str, Any]]) -> Tuple[int, str, str]:
    """
    Calculate an explainable risk score (0-99) and classification based on static findings.
    Returns: (risk_score, risk_classification, explanation)
    """
    if not findings:
        return 0, "CLEAN", "No security anomalies or potential threats were detected during the static scan."

    # Group counts by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Base score heuristics
    score = 0
    reasons = []

    if severity_counts["CRITICAL"] > 0:
        # Critical threats like pickle code execution or confirmed embedded payloads
        score = 90 + min(severity_counts["CRITICAL"] * 3, 9)  # Cap critical additions at 99
        reasons.append(f"Detected {severity_counts['CRITICAL']} CRITICAL threat indicator(s), including potential remote code execution or embedded files.")
    elif severity_counts["HIGH"] > 0:
        # High issues like NaNs, Infs, or massive outliers
        score = 50 + min(severity_counts["HIGH"] * 5, 30)     # Cap high additions at 80
        reasons.append(f"Detected {severity_counts['HIGH']} HIGH severity indicator(s) (e.g., NaN/Inf values, extreme weight outliers, custom operators).")
    elif severity_counts["MEDIUM"] > 0:
        # Medium issues like suspicious bias distributions, constant layers
        score = 25 + min(severity_counts["MEDIUM"] * 3, 20)    # Cap medium additions at 45
        reasons.append(f"Detected {severity_counts['MEDIUM']} MEDIUM severity indicator(s) (e.g., Trojan/bias anomalies, inactive layers).")
    elif severity_counts["LOW"] > 0:
        # Low issues like high LSB entropy, legacy format
        score = 5 + min(severity_counts["LOW"] * 2, 15)       # Cap low additions at 20
        reasons.append(f"Detected {severity_counts['LOW']} LOW severity indicator(s) (e.g., format warnings, minor statistical deviations).")
    else:
        # Info only
        score = 0
        reasons.append("Only informational indicators were discovered. Model structure is within normal limits.")

    # Determine classification
    if score >= 80:
        classification = "HIGH RISK"
    elif score >= 25:
        classification = "SUSPICIOUS"
    else:
        # Even with low findings, if there are some findings we classify as SUSPICIOUS or CLEAN based on score threshold
        classification = "CLEAN" if score < 15 else "SUSPICIOUS"

    explanation = " ".join(reasons)
    
    # Strictly cap at 99 (never claim 100% certainty)
    score = min(max(score, 0), 99)

    return score, classification, explanation
