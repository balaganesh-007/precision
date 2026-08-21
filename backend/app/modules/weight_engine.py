import os
import logging
import numpy as np
from typing import List, Dict, Any
from backend.app.modules.base import BaseModule

logger = logging.getLogger("weight_engine")

class WeightEngine(BaseModule):
    @property
    def name(self) -> str:
        return "weight_engine"

    def scan(self, filepath: str, format: str) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(filepath):
            return findings

        if format == 'ONNX':
            findings.extend(self._scan_onnx(filepath))
        elif format == 'SAFETENSORS':
            findings.extend(self._scan_safetensors(filepath))
        elif format == 'PYTORCH':
            # Documented warning about format safety
            findings.append({
                "severity": "LOW",
                "module": self.name,
                "title": "Legacy Pickle-Based Format",
                "description": (
                    "This model is stored in the PyTorch pickle format. Weight distribution analysis is skipped "
                    "for safety (to prevent executing pickled components). Safe static opcode scanning was executed instead."
                ),
                "layer_name": None,
                "evidence": {
                    "format": "PYTORCH",
                    "reason": "Skip dynamic weights loading to prevent pickle-deserialization risk."
                }
            })
        return findings

    def _analyze_tensor(self, weights: np.ndarray, name: str) -> List[Dict[str, Any]]:
        findings = []
        
        # 1. Check for NaN
        if np.isnan(weights).any():
            nan_count = int(np.isnan(weights).sum())
            findings.append({
                "severity": "HIGH",
                "module": self.name,
                "title": "NaN Values Detected in Weights",
                "description": f"Layer '{name}' contains {nan_count} NaN (Not a Number) weight values. This indicates a corrupted or tampered model.",
                "layer_name": name,
                "evidence": {
                    "nan_count": nan_count,
                    "layer_shape": list(weights.shape)
                }
            })

        # 2. Check for Inf
        if np.isinf(weights).any():
            inf_count = int(np.isinf(weights).sum())
            findings.append({
                "severity": "HIGH",
                "module": self.name,
                "title": "Infinite Values Detected in Weights",
                "description": f"Layer '{name}' contains {inf_count} infinite (Inf) weight values, which will crash standard inference engines.",
                "layer_name": name,
                "evidence": {
                    "inf_count": inf_count,
                    "layer_shape": list(weights.shape)
                }
            })

        # Filter out NaN/Inf for statistical calculations
        valid_weights = weights[np.isfinite(weights)]
        if len(valid_weights) == 0:
            return findings

        # 3. Check for extreme outliers (values greater than 1e6 in magnitude)
        max_val = float(np.max(valid_weights))
        min_val = float(np.min(valid_weights))
        abs_max = max(abs(max_val), abs(min_val))
        
        if abs_max > 1e6:
            findings.append({
                "severity": "HIGH",
                "module": self.name,
                "title": "Extreme Weight Value Outlier",
                "description": f"Layer '{name}' has a weight value of magnitude {abs_max:.2e}, which is extremely anomalous for typical machine learning weights (usually between -10 and 10).",
                "layer_name": name,
                "evidence": {
                    "max_value": max_val,
                    "min_value": min_val,
                    "abs_max": abs_max,
                    "layer_shape": list(weights.shape)
                }
            })

        # 4. Check for dead/constant layers (except tiny bias layers)
        if len(valid_weights) > 10:
            std_dev = float(np.std(valid_weights))
            mean_val = float(np.mean(valid_weights))
            
            if std_dev < 1e-7:
                findings.append({
                    "severity": "MEDIUM",
                    "module": self.name,
                    "title": "Constant/Dead Weight Layer",
                    "description": f"Layer '{name}' has almost zero variance (std dev: {std_dev:.2e}), indicating it is inactive or filled with constant values.",
                    "layer_name": name,
                    "evidence": {
                        "std_dev": std_dev,
                        "mean": mean_val,
                        "layer_shape": list(weights.shape)
                    }
                })

        return findings

    def _scan_onnx(self, filepath: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            import onnx
            from onnx import numpy_helper
            
            # Load ONNX structure without execution
            model = onnx.load(filepath)
            initializers = model.graph.initializer
            
            if not initializers:
                findings.append({
                    "severity": "INFO",
                    "module": self.name,
                    "title": "No Model Initializers Found",
                    "description": "The ONNX model does not contain any weight initializers (may be a graph definition only).",
                    "layer_name": None,
                    "evidence": {}
                })
                return findings

            for initializer in initializers:
                try:
                    name = initializer.name
                    weights = numpy_helper.to_array(initializer)
                    findings.extend(self._analyze_tensor(weights, name))
                except Exception as e:
                    logger.warning(f"Error parsing tensor {initializer.name} in ONNX: {e}")
                    
        except Exception as e:
            findings.append({
                "severity": "HIGH",
                "module": self.name,
                "title": "Failed to Parse ONNX Structure",
                "description": f"Failed to statically parse ONNX model file: {str(e)}",
                "layer_name": None,
                "evidence": {"error": str(e)}
            })
        return findings

    def _scan_safetensors(self, filepath: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            from safetensors import safe_open
            
            with safe_open(filepath, framework="numpy", device="cpu") as f:
                keys = f.keys()
                if not keys:
                    findings.append({
                        "severity": "INFO",
                        "module": self.name,
                        "title": "Empty Safetensors File",
                        "description": "The Safetensors file contains no tensor keys.",
                        "layer_name": None,
                        "evidence": {}
                    })
                    return findings

                for name in keys:
                    try:
                        weights = f.get_tensor(name)
                        findings.extend(self._analyze_tensor(weights, name))
                    except Exception as e:
                        logger.warning(f"Error extracting tensor {name} in Safetensors: {e}")
                        
        except Exception as e:
            findings.append({
                "severity": "HIGH",
                "module": self.name,
                "title": "Failed to Parse Safetensors Header",
                "description": f"Failed to statically read Safetensors header metadata: {str(e)}",
                "layer_name": None,
                "evidence": {"error": str(e)}
            })
        return findings
