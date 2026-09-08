import io
import pickletools
import logging
from typing import List, Dict, Any

logger = logging.getLogger("pickle_scanner")

DANGEROUS_MODULES = {
    "os",
    "posix",
    "nt",
    "subprocess",
    "sys",
    "shutil",
    "socket",
    "requests",
    "urllib",
    "urllib2",
    "urllib3",
    "importlib",
}

DANGEROUS_CALLABLES = {
    "system",
    "popen",
    "exec",
    "eval",
    "execfile",
    "compile",
    "run",
    "call",
    "check_call",
    "check_output",
    "Popen",
    "spawn",
    "spawnv",
    "fork",
    "load",
    "loads",
    "getattr",
    "setattr",
    "__import__",
    "import_module",
    "remove",
    "rmtree",
    "unlink",
}


def scan_pytorch_pickle(filepath: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    try:
        dangerous_refs = _extract_dangerous_globals(filepath)

    except Exception as exc:
        logger.warning(
            "Failed to statically disassemble pickle '%s': %s",
            filepath,
            exc,
        )

        findings.append({
            "severity": "MEDIUM",
            "module": "pickle_scanner",
            "title": "Pickle Structure Could Not Be Fully Parsed",
            "description": (
                "The file could not be fully disassembled as a "
                "standard pickle stream."
            ),
            "layer_name": None,
            "evidence": {"error": str(exc)},
        })

        return findings

    if dangerous_refs:
        findings.append({
            "severity": "CRITICAL",
            "module": "pickle_scanner",
            "title": "Dangerous Pickle Import Reference Detected",
            "description": (
                f"Found {len(dangerous_refs)} dangerous reference(s) "
                "in the pickle opcode stream capable of arbitrary "
                "code execution during unsafe deserialization."
            ),
            "layer_name": None,
            "evidence": {
                "dangerous_references": dangerous_refs[:20],
                "total_dangerous_references": len(dangerous_refs),
            },
        })
    else:
        findings.append({
            "severity": "INFO",
            "module": "pickle_scanner",
            "title": "No Dangerous Pickle References Found",
            "description": (
                "Static disassembly found no references to known "
                "dangerous modules or callables."
            ),
            "layer_name": None,
            "evidence": {},
        })

    return findings


def _extract_dangerous_globals(
    filepath: str,
) -> List[Dict[str, str]]:

    dangerous_refs: List[Dict[str, str]] = []

    with open(filepath, "rb") as f:
        data = f.read()

    pickle_streams = _extract_pickle_streams(data)

    for stream in pickle_streams:
        try:
            pending_strings: List[str] = []

            for opcode, arg, _pos in pickletools.genops(
                io.BytesIO(stream)
            ):

                if opcode.name == "GLOBAL" and isinstance(arg, str):
                    parts = arg.replace("\n", " ").split(" ")

                    if len(parts) == 2:
                        module_name, callable_name = parts

                        if _is_dangerous(
                            module_name,
                            callable_name,
                        ):
                            dangerous_refs.append({
                                "module": module_name,
                                "callable": callable_name,
                            })

                    pending_strings = []
                    continue

                if opcode.name in (
                    "SHORT_BINUNICODE",
                    "BINUNICODE",
                    "BINUNICODE8",
                    "UNICODE",
                ) and isinstance(arg, str):

                    pending_strings.append(arg)
                    pending_strings = pending_strings[-2:]
                    continue

                if opcode.name == "STACK_GLOBAL":
                    if len(pending_strings) == 2:
                        module_name, callable_name = pending_strings

                        if _is_dangerous(
                            module_name,
                            callable_name,
                        ):
                            dangerous_refs.append({
                                "module": module_name,
                                "callable": callable_name,
                            })

                    pending_strings = []
                    continue

                if opcode.name in (
                    "MEMOIZE",
                    "PUT",
                    "BINPUT",
                    "LONG_BINPUT",
                ):
                    continue

                pending_strings = []

        except Exception as exc:
            logger.debug(
                "Skipping unparseable pickle segment: %s",
                exc,
            )
            continue

    return dangerous_refs


def _extract_pickle_streams(data: bytes) -> List[bytes]:
    streams: List[bytes] = []

    if data[:2] == b"PK":
        try:
            import zipfile

            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for name in zf.namelist():
                    if (
                        name.endswith(".pkl")
                        or name.endswith("data.pkl")
                    ):
                        streams.append(zf.read(name))

        except Exception as exc:
            logger.debug(
                "Failed to read zip-based pickle archive: %s",
                exc,
            )

        if streams:
            return streams

    streams.append(data)

    return streams


def _is_dangerous(
    module_name: str,
    callable_name: str,
) -> bool:

    top_level = module_name.split(".")[0]

    if top_level in DANGEROUS_MODULES:
        return True

    if callable_name in DANGEROUS_CALLABLES:
        return True

    return False


def calculate_risk(
    findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Calculate overall model security risk.
    """

    severity_points = {
        "CRITICAL": 40,
        "HIGH": 25,
        "MEDIUM": 10,
        "LOW": 3,
        "INFO": 0,
    }

    score = 0

    for finding in findings:
        severity = str(
            finding.get("severity", "INFO")
        ).upper()

        score += severity_points.get(
            severity,
            0,
        )

    score = min(max(score, 0), 100)

    if score >= 70:
        risk_level = "CRITICAL"
    elif score >= 40:
        risk_level = "HIGH"
    elif score >= 15:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "explanation": (
            f"Model risk score is {score}/100 based on "
            f"{len(findings)} security finding(s)."
        ),
    }