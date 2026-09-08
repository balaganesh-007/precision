import os
import json
import datetime
import logging
from sqlalchemy.orm import Session
from backend.app.models import Scan, Finding, Report, Model
from backend.app.modules.weight_engine import WeightEngine
from backend.app.modules.stego_detector import StegoDetector
from backend.app.modules.behavior_analyzer import BehaviorAnalyzer
from backend.app.utils.pickle_scanner import scan_pytorch_pickle
from backend.app.core.risk_engine import calculate_risk
from backend.app.config import settings

logger = logging.getLogger("orchestrator")

def generate_markdown_report(model: Model, scan: Scan, findings: list) -> str:
    """Generate a clean markdown report summarizing the security details."""
    report_content = []
    report_content.append(f"# AI Model Security Scan Report")
    report_content.append(f"**Date:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC  ")
    report_content.append(f"**Model Name:** {model.name}  ")
    report_content.append(f"**Model Format:** {model.format}  ")
    report_content.append(f"**SHA-256 Hash:** `{model.sha256_hash}`  ")
    report_content.append(f"**File Size:** {model.file_size:,} bytes  \n")

    report_content.append(f"## Security Status Assessment")
    report_content.append(f"- **Risk Classification:** **{scan.risk_classification}**")
    report_content.append(f"- **Risk Score:** **{scan.risk_score}/100**\n")

    report_content.append(f"### Recommendations")
    if scan.risk_classification == "HIGH RISK":
        report_content.append(
            "> [!CAUTION]\n"
            "> **DO NOT USE THIS MODEL IN PRODUCTION.**\n"
            "> Serious security anomalies or execution vulnerability risks were detected. "
            "Please review the findings details below and replace the model file with a verified source."
        )
    elif scan.risk_classification == "SUSPICIOUS":
        report_content.append(
            "> [!WARNING]\n"
            "> **USE WITH CAUTION.**\n"
            "> Minor anomalies (such as weights outliers or unusual entropy) were detected. "
            "It is recommended to run additional validation or verify the training dataset source."
        )
    else:
        report_content.append(
            "> [!NOTE]\n"
            "> **MODEL IS CLEAN.**\n"
            "> No suspicious elements or steganographic patterns were identified. Normal operations are recommended."
        )

    report_content.append(f"\n## Findings Log ({len(findings)})")
    if not findings:
        report_content.append("No findings recorded. All static tests passed.")
    else:
        for idx, f in enumerate(findings, 1):
            severity_tag = f"[{f['severity']}]"
            layer_name = f.get("layer_name")
            layer_info = f" (Layer: {layer_name})" if layer_name else ""
            report_content.append(f"### {idx}. {severity_tag} {f['title']}{layer_info}")
            report_content.append(f"**Module:** `{f['module']}`  ")
            report_content.append(f"**Description:** {f['description']}  ")
            if f.get("evidence"):
                report_content.append(f"**Evidence Details:**")
                try:
                    evidence_json = json.dumps(f["evidence"], indent=2, default=str)
                except (TypeError, ValueError):
                    evidence_json = str(f["evidence"])
                report_content.append(f"```json\n{evidence_json}\n```")
            report_content.append("\n" + "-"*40 + "\n")

    report_content.append(f"\n*Disclaimer: This is a defensive scanning report based on static analysis. Risk classification is heuristic and does not guarantee absolute safety or threat absence.*")
    return "\n".join(report_content)

def run_model_scan(db: Session, scan_id: int):
    """
    Run security scan statically across all modules.
    This runs inside a background thread/task.
    """
    logger.info(f"Starting background security scan for Scan ID: {scan_id}")

    # Fetch Scan details
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        logger.error(f"Scan ID {scan_id} not found in database.")
        return

    model = db.query(Model).filter(Model.id == scan.model_id).first()
    if not model:
        logger.error(f"Model ID {scan.model_id} not found in database.")
        scan.status = "FAILED"
        scan.error_message = "Associated model file metadata missing."
        db.commit()
        return

    model_path = os.path.join(settings.UPLOAD_DIR, f"{model.sha256_hash}_{model.name}")
    if not os.path.exists(model_path):
        # Fallback to test models directory if file is in test folder or not found in uploads
        test_model_path = os.path.join("test_models", model.name)
        if os.path.exists(test_model_path):
            model_path = test_model_path
        else:
            logger.error(f"Model file not found at {model_path} or {test_model_path}")
            scan.status = "FAILED"
            scan.error_message = f"Model file '{model.name}' not found on server disk."
            db.commit()
            return

    try:
        # Update state to RUNNING
        scan.status = "RUNNING"
        db.commit()

        all_findings = []
        normalized_format = (model.format or "").upper()

        # 1. Format-specific scans (e.g. static Pickle check for PyTorch format)
        has_critical_exploit = False
        if normalized_format == 'PYTORCH':
            logger.info("Executing static pickle scanner...")
            pickle_findings = scan_pytorch_pickle(model_path)
            for f in pickle_findings:
                f["module"] = "FORMAT"  # Mark as format scanner finding
                all_findings.append(f)

            has_critical_exploit = any(
                f.get("severity") == "CRITICAL" for f in pickle_findings
            )

        # 2. Run other analyzers only if no critical exploit was already found.
        # A confirmed pickle-based exploit means the file is unsafe to process
        # further; deeper static analysis wouldn't change the verdict.
        if not has_critical_exploit:
            weight_engine = WeightEngine()
            stego_detector = StegoDetector()
            behavior_analyzer = BehaviorAnalyzer()

            logger.info("Executing static weight statistics checks...")
            all_findings.extend(weight_engine.scan(model_path, model.format))

            logger.info("Executing static LSB steganography checks...")
            all_findings.extend(stego_detector.scan(model_path, model.format))

            logger.info("Executing static graph behavior/bias checks...")
            all_findings.extend(behavior_analyzer.scan(model_path, model.format))
        else:
            logger.warning(
                "Critical pickle exploit detected for Scan ID %s; "
                "skipping further static analyzers.",
                scan_id,
            )

        # 3. Calculate Risk Score
        score, classification, explanation = calculate_risk(all_findings)

        # 4. Save findings to Database
        db_findings = []
        for f in all_findings:
            db_finding = Finding(
                scan_id=scan.id,
                severity=f["severity"],
                module=f["module"],
                title=f["title"],
                description=f["description"],
                layer_name=f.get("layer_name"),
                evidence=f.get("evidence")
            )
            db.add(db_finding)
            db_findings.append(db_finding)

        # Flush to generate IDs
        db.flush()

        # Update scan variables
        scan.status = "COMPLETED"
        scan.risk_score = score
        scan.risk_classification = classification
        scan.completed_at = datetime.datetime.utcnow()

        # 5. Generate and store Report
        report_dir = os.path.join(settings.UPLOAD_DIR, "reports")
        os.makedirs(report_dir, exist_ok=True)
        report_filename = f"report_{scan.id}.md"
        report_path = os.path.join(report_dir, report_filename)

        report_md = generate_markdown_report(model, scan, all_findings)
        with open(report_path, "w", encoding="utf-8") as rf:
            rf.write(report_md)

        db_report = Report(
            scan_id=scan.id,
            report_path=report_path
        )
        db.add(db_report)

        db.commit()
        logger.info(f"Scan {scan_id} completed successfully. Score: {score}, Class: {classification}")

    except Exception as e:
        logger.exception(f"Scan {scan_id} failed during execution.")
        db.rollback()
        scan.status = "FAILED"
        scan.error_message = f"Scanning exception: {str(e)}"
        scan.completed_at = datetime.datetime.utcnow()
        db.commit()