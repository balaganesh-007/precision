import os
import logging
from typing import List, Dict, Any

import numpy as np

from backend.app.modules.base import BaseModule


logger = logging.getLogger("weight_engine")


class WeightEngine(BaseModule):

    @property
    def name(self) -> str:
        return "weight_engine"

    def scan(self, filepath: str, format: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        if not os.path.exists(filepath):
            return findings

        normalized_format = (format or "").upper()

        try:
            if normalized_format == "ONNX":
                findings.extend(self._scan_onnx(filepath))

            elif normalized_format == "SAFETENSORS":
                findings.extend(self._scan_safetensors(filepath))

            elif normalized_format in {"PYTORCH", "PTH", "PT"}:
                findings.append({
                    "severity": "LOW",
                    "module": self.name,
                    "title": "Legacy Pickle-Based Format",
                    "description": (
                        "This model uses a PyTorch pickle-based format. "
                        "Weight loading is skipped for safety to avoid "
                        "pickle deserialization risks."
                    ),
                    "layer_name": None,
                    "evidence": {
                        "format": format,
                        "reason": "Dynamic weight loading skipped for safety."
                    }
                })

            else:
                findings.append({
                    "severity": "INFO",
                    "module": self.name,
                    "title": "Unsupported Format for Weight Analysis",
                    "description": (
                        f"Weight-level analysis is not supported for "
                        f"format '{format}'."
                    ),
                    "layer_name": None,
                    "evidence": {"format": format}
                })

        except Exception as e:
            logger.exception("Weight scan failed: %s", e)

        return findings

    def _analyze_tensor(
        self,
        weights: np.ndarray,
        name: str
    ) -> List[Dict[str, Any]]:

        findings: List[Dict[str, Any]] = []

        # Convert to NumPy array
        weights = np.asarray(weights)

        # Skip non-numeric tensors
        if not np.issubdtype(weights.dtype, np.number):
            return findings

        # 1. Check for NaN values
        nan_mask = np.isnan(weights)

        if nan_mask.any():
            nan_count = int(nan_mask.sum())

            findings.append({
                "severity": "HIGH",
                "module": self.name,
                "title": "NaN Values Detected in Weights",
                "description": (
                    f"Layer '{name}' contains {nan_count} NaN "
                    "(Not a Number) weight values."
                ),
                "layer_name": name,
                "evidence": {
                    "nan_count": nan_count,
                    "layer_shape": list(weights.shape)
                }
            })

        # 2. Check for infinite values
        inf_mask = np.isinf(weights)

        if inf_mask.any():
            inf_count = int(inf_mask.sum())

            findings.append({
                "severity": "HIGH",
                "module": self.name,
                "title": "Infinite Values Detected in Weights",
                "description": (
                    f"Layer '{name}' contains {inf_count} "
                    "infinite weight values."
                ),
                "layer_name": name,
                "evidence": {
                    "inf_count": inf_count,
                    "layer_shape": list(weights.shape)
                }
            })

        # Keep only finite values for statistics
        valid_weights = weights[np.isfinite(weights)]

        if valid_weights.size == 0:
            return findings

        # 3. Check for extreme outliers
        max_val = float(np.max(valid_weights))
        min_val = float(np.min(valid_weights))
        abs_max = max(abs(max_val), abs(min_val))

        if abs_max > 1e6:
            findings.append({
                "severity": "HIGH",
                "module": self.name,
                "title": "Extreme Weight Value Outlier",
                "description": (
                    f"Layer '{name}' contains an extremely large "
                    f"weight value with magnitude {abs_max:.2e}."
                ),
                "layer_name": name,
                "evidence": {
                    "max_value": max_val,
                    "min_value": min_val,
                    "abs_max": abs_max,
                    "layer_shape": list(weights.shape)
                }
            })

        # 4. Check for nearly constant/dead layers
        if valid_weights.size > 10:
            std_dev = float(np.std(valid_weights))
            mean_val = float(np.mean(valid_weights))

            if std_dev < 1e-7:
                findings.append({
                    "severity": "MEDIUM",
                    "module": self.name,
                    "title": "Constant/Dead Weight Layer",
                    "description": (
                        f"Layer '{name}' has almost zero variance "
                        f"(std dev: {std_dev:.2e})."
                    ),
                    "layer_name": name,
                    "evidence": {
                        "std_dev": std_dev,
                        "mean": mean_val,
                        "layer_shape": list(weights.shape)
                    }
                })

        return findings

    def _scan_onnx(self, filepath: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        try:
            import onnx
            from onnx import numpy_helper

            # Load ONNX model without executing it
            model = onnx.load(filepath)

            initializers = model.graph.initializer

            if not initializers:
                findings.append({
                    "severity": "INFO",
                    "module": self.name,
                    "title": "No Model Initializers Found",
                    "description": (
                        "The ONNX model does not contain any "
                        "weight initializers."
                    ),
                    "layer_name": None,
                    "evidence": {}
                })

                return findings

            for initializer in initializers:
                try:
                    name = initializer.name
                    weights = numpy_helper.to_array(initializer)

                    tensor_findings = self._analyze_tensor(
                        weights,
                        name
                    )

                    findings.extend(tensor_findings)

                except Exception as e:
                    logger.warning(
                        "Error parsing tensor %s: %s",
                        initializer.name,
                        e
                    )

        except Exception as e:
            findings.append({
                "severity": "HIGH",
                "module": self.name,
                "title": "Failed to Parse ONNX Structure",
                "description": (
                    f"Failed to statically parse ONNX model: {str(e)}"
                ),
                "layer_name": None,
                "evidence": {
                    "error": str(e)
                }
            })

        return findings

    def _scan_safetensors(
        self,
        filepath: str
    ) -> List[Dict[str, Any]]:

        findings: List[Dict[str, Any]] = []

        try:
            from safetensors import safe_open

            with safe_open(
                filepath,
                framework="numpy",
                device="cpu"
            ) as f:

                keys = list(f.keys())

                if not keys:
                    findings.append({
                        "severity": "INFO",
                        "module": self.name,
                        "title": "Empty Safetensors File",
                        "description": (
                            "The Safetensors file contains no tensors."
                        ),
                        "layer_name": None,
                        "evidence": {}
                    })

                    return findings

                for name in keys:
                    try:
                        weights = f.get_tensor(name)

                        tensor_findings = self._analyze_tensor(
                            weights,
                            name
                        )

                        findings.extend(tensor_findings)

                    except Exception as e:
                        logger.warning(
                            "Error extracting tensor %s: %s",
                            name,
                            e
                        )

        except Exception as e:
            findings.append({
                "severity": "HIGH",
                "module": self.name,
                "title": "Failed to Parse Safetensors File",
                "description": (
                    f"Failed to statically read Safetensors file: "
                    f"{str(e)}"
                ),
                "layer_name": None,
                "evidence": {
                    "error": str(e)
                }
            })

        return findings