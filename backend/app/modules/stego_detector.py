import logging
from typing import Any, Dict, List

import numpy as np

from backend.app.modules.base import BaseModule


logger = logging.getLogger("stego_detector")


class StegoDetector(BaseModule):
    """
    Static detector for demonstration steganography markers.

    This module:
    1. Scans raw model bytes for an exact demonstration marker.
    2. Scans ONNX tensor bytes for the exact marker.
    3. Reconstructs LSB data (per-element, in tensor traversal order)
       and checks for the exact marker.
    4. Does not classify short/random binary patterns such as "MZ"
       as malicious, preventing false positives.

    No model inference or unsafe deserialization is performed.
    """

    DEMO_MARKER = b"STEGO_DEMO_MARKER_2026"

    @property
    def name(self) -> str:
        return "stego_detector"

    def scan(self, filepath: str, format: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        normalized_format = (format or "").upper()

        raw_findings = self._scan_raw_file(filepath)
        findings.extend(raw_findings)

        if any(f.get("severity") == "CRITICAL" for f in findings):
            return findings

        if normalized_format in {"PYTORCH", "PTH", "PT"}:
            findings.append(
                {
                    "severity": "INFO",
                    "module": self.name,
                    "title": "Deep Tensor Analysis Skipped",
                    "description": (
                        "Tensor-level analysis was skipped because this "
                        "format may require unsafe deserialization. "
                        "Raw-file static analysis was completed."
                    ),
                    "layer_name": None,
                    "evidence": {"format": format},
                }
            )
            return findings

        if normalized_format != "ONNX":
            return findings

        try:
            import onnx
            from onnx import numpy_helper

            model = onnx.load(filepath)

            for initializer in model.graph.initializer:
                try:
                    weights = numpy_helper.to_array(initializer)
                    tensor_findings = self._analyze_tensor(initializer.name, weights)
                    findings.extend(tensor_findings)

                    if any(f.get("severity") == "CRITICAL" for f in tensor_findings):
                        return findings

                except Exception as exc:
                    logger.warning(
                        "Failed to analyze tensor '%s': %s", initializer.name, exc
                    )

        except ImportError:
            logger.warning("ONNX library is not installed. ONNX tensor analysis skipped.")
        except Exception as exc:
            logger.warning("Failed to scan ONNX model '%s': %s", filepath, exc)

        return findings

    def _scan_raw_file(self, filepath: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            with open(filepath, "rb") as file:
                raw_data = file.read()

            position = raw_data.find(self.DEMO_MARKER)
            if position != -1:
                marker_text = self.DEMO_MARKER.decode("utf-8", errors="ignore")
                findings.append(
                    {
                        "severity": "CRITICAL",
                        "module": self.name,
                        "title": "Steganographic Marker Detected",
                        "description": (
                            f"MODEL_FILE contains the exact hidden "
                            f"demonstration marker '{marker_text}'."
                        ),
                        "layer_name": "MODEL_FILE",
                        "evidence": {
                            "marker_found": marker_text,
                            "position": position,
                            "source": "raw model file",
                        },
                    }
                )
        except Exception as exc:
            logger.warning("Failed to perform raw file analysis on '%s': %s", filepath, exc)

        return findings

    def _analyze_tensor(self, layer_name: str, weights: Any) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        try:
            array = np.asarray(weights).flatten()
            if array.size == 0:
                return findings

            # 1. Direct raw tensor byte check
            raw_bytes = array.tobytes()
            position = raw_bytes.find(self.DEMO_MARKER)
            if position != -1:
                return [self._critical_finding(
                    layer_name, position, "tensor raw bytes",
                    "raw bytes"
                )]

            # 2. Extract one LSB per element, preserving element order
            if np.issubdtype(array.dtype, np.floating):
                if array.dtype == np.float64:
                    values = array.astype(np.float64, copy=False).view(np.uint64)
                else:
                    values = array.astype(np.float32, copy=False).view(np.uint32)
            elif np.issubdtype(array.dtype, np.integer):
                values = array.astype(np.uint64, copy=False)
            else:
                return findings

            lsb_bits = (values & 1).astype(np.uint8)

            usable_length = (len(lsb_bits) // 8) * 8
            lsb_bits = lsb_bits[:usable_length]
            if len(lsb_bits) < 8:
                return findings

            # 3. Normal bit-order reconstruction (bit i of byte j = LSB of
            #    element j*8 + i, in original tensor traversal order)
            normal_bytes = self._bits_to_bytes(lsb_bits)
            position = normal_bytes.find(self.DEMO_MARKER)
            if position != -1:
                return [self._critical_finding(
                    layer_name, position, "normal-bit LSB reconstruction",
                    "normal-order LSB data"
                )]

            # 4. Reversed bit-order reconstruction (per byte, MSB-first)
            reversed_bits = lsb_bits.reshape(-1, 8)[:, ::-1].flatten()
            reversed_bytes = self._bits_to_bytes(reversed_bits)
            position = reversed_bytes.find(self.DEMO_MARKER)
            if position != -1:
                return [self._critical_finding(
                    layer_name, position, "reversed-bit LSB reconstruction",
                    "reversed-order LSB data"
                )]

            # 5. Conservative statistical observation only (never CRITICAL/HIGH alone)
            total_bits = len(lsb_bits)
            if total_bits >= 4096:
                ones = int(np.sum(lsb_bits))
                zeros = total_bits - ones
                p_one = ones / total_bits
                p_zero = zeros / total_bits

                entropy = 0.0
                if p_one > 0:
                    entropy -= p_one * np.log2(p_one)
                if p_zero > 0:
                    entropy -= p_zero * np.log2(p_zero)

                if entropy > 0.9999 and abs(ones - zeros) <= max(10, total_bits * 0.001):
                    findings.append(
                        {
                            "severity": "LOW",
                            "module": self.name,
                            "title": "Highly Uniform LSB Distribution",
                            "description": (
                                f"Layer '{layer_name}' has an unusually uniform "
                                f"least-significant-bit distribution. This is only "
                                f"a statistical observation and is not proof of a "
                                f"hidden payload."
                            ),
                            "layer_name": layer_name,
                            "evidence": {
                                "lsb_entropy": round(float(entropy), 6),
                                "ones_count": ones,
                                "zeros_count": zeros,
                                "total_bits": total_bits,
                            },
                        }
                    )

        except Exception as exc:
            logger.warning("Failed to analyze layer '%s': %s", layer_name, exc)

        return findings

    def _critical_finding(
        self, layer_name: str, position: int, source: str, source_desc: str
    ) -> Dict[str, Any]:
        marker_text = self.DEMO_MARKER.decode("utf-8", errors="ignore")
        return {
            "severity": "CRITICAL",
            "module": self.name,
            "title": "Hidden Payload Marker Detected",
            "description": (
                f"Layer '{layer_name}' contains the exact hidden marker "
                f"'{marker_text}' in {source_desc}."
            ),
            "layer_name": layer_name,
            "evidence": {
                "marker_found": marker_text,
                "position": position,
                "source": source,
            },
        }

    @staticmethod
    def _bits_to_bytes(bits: Any) -> bytes:
        try:
            bits = np.asarray(bits, dtype=np.uint8)
            usable_length = (len(bits) // 8) * 8
            bits = bits[:usable_length]
            if len(bits) == 0:
                return b""
            return np.packbits(bits).tobytes()
        except Exception as exc:
            logger.warning("Failed to reconstruct bytes from LSB bits: %s", exc)
            return b""