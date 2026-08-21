import os
import logging
from typing import List, Dict, Any
from backend.app.modules.base import BaseModule

logger = logging.getLogger("behavior_analyzer")

# Standard ONNX domains/operators. Custom nodes outside this set are flagged.
STANDARD_DOMAINS = {"", "ai.onnx", "ai.onnx.ml", "ai.onnx.training"}

class BehaviorAnalyzer(BaseModule):
    @property
    def name(self) -> str:
        return "behavior_analyzer"

    def scan(self, filepath: str, format: str) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(filepath):
            return findings

        if format == 'ONNX':
            findings.extend(self._scan_onnx_graph(filepath))
        elif format == 'SAFETENSORS':
            findings.append({
                "severity": "INFO",
                "module": self.name,
                "title": "Safetensors Format Inherent Safety",
                "description": (
                    "Safetensors only stores raw weight values and headers. It does not define a computational graph "
                    "or custom code execution pathways, making it inherently safe from model-graph runtime exploits."
                ),
                "layer_name": None,
                "evidence": {
                    "format": "SAFETENSORS",
                    "graph_included": False
                }
            })
        elif format == 'PYTORCH':
            findings.append({
                "severity": "INFO",
                "module": self.name,
                "title": "Computation Graph Analysis Skipped",
                "description": (
                    "This model is in PyTorch format. Statically parsing a PyTorch computation graph requires "
                    "deserializing code elements, which was skipped to prevent execution. Safe static pickle scanning was performed instead."
                ),
                "layer_name": None,
                "evidence": {
                    "format": "PYTORCH"
                }
            })
            
        return findings

    def _scan_onnx_graph(self, filepath: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            import onnx
            import numpy as np
            
            # Load ONNX model structure statically
            model = onnx.load(filepath)
            graph = model.graph
            
            # 1. Scan for custom operators / non-standard domains
            custom_nodes = []
            for node in graph.node:
                domain = node.domain
                if domain not in STANDARD_DOMAINS:
                    custom_nodes.append({
                        "name": node.name,
                        "op_type": node.op_type,
                        "domain": domain
                    })
            
            if custom_nodes:
                findings.append({
                    "severity": "HIGH",
                    "module": self.name,
                    "title": "Non-Standard Custom Operators Detected",
                    "description": (
                        f"Found {len(custom_nodes)} nodes in the model graph that use custom or unregistered "
                        f"operators (e.g. outside official ONNX schemas). Custom nodes can trigger unverified code "
                        f"pathways in the model runtime engine."
                    ),
                    "layer_name": None,
                    "evidence": {
                        "custom_nodes": custom_nodes[:10],
                        "total_custom_nodes": len(custom_nodes)
                    }
                })

            # 2. Scan biases for suspicious Trojan/Backdoor gating patterns
            # A common way to bake in backdoors (Trojans) statically is via massive, highly skewed bias values
            # that act as switches, overriding normal activations when a specific trigger triggers a node.
            suspicious_biases = []
            for initializer in graph.initializer:
                name = initializer.name
                # Biases are typically 1D tensors, often containing "bias" in their name
                if "bias" in name.lower() or len(initializer.dims) == 1:
                    try:
                        from onnx import numpy_helper
                        bias_arr = numpy_helper.to_array(initializer)
                        if len(bias_arr) > 0:
                            # Filter out inf/nan which are handled by weight engine
                            clean_biases = bias_arr[np.isfinite(bias_arr)]
                            if len(clean_biases) > 1:
                                max_bias = float(np.max(np.abs(clean_biases)))
                                std_bias = float(np.std(clean_biases))
                                
                                # Flag if standard deviation or absolute bias is extremely high
                                # (e.g., bias magnitude > 1000 in a normal scale model)
                                if max_bias > 1000.0 or std_bias > 500.0:
                                    suspicious_biases.append({
                                        "name": name,
                                        "max_absolute_value": max_bias,
                                        "std_dev": std_bias
                                    })
                    except Exception as e:
                        logger.warning(f"Error checking bias tensor {name}: {e}")

            if suspicious_biases:
                findings.append({
                    "severity": "MEDIUM",
                    "module": self.name,
                    "title": "Suspicious Bias Distribution (Potential Trojan Gating)",
                    "description": (
                        f"Detected {len(suspicious_biases)} bias/gating tensors with extremely large values or "
                        f"standard deviations. This can indicate backdoor/Trojan triggering channels built into the weights."
                    ),
                    "layer_name": suspicious_biases[0]["name"],
                    "evidence": {
                        "suspicious_biases": suspicious_biases,
                        "heuristic": "Bias magnitude exceeds typical threshold of 1000.0"
                    }
                })

        except Exception as e:
            logger.debug(f"Behavior analyzer failed to parse ONNX: {e}")
            findings.append({
                "severity": "LOW",
                "module": self.name,
                "title": "ONNX Graph Validation Incomplete",
                "description": f"Static graph scan failed to check ONNX structural nodes: {str(e)}",
                "layer_name": None,
                "evidence": {"error": str(e)}
            })
            
        return findings
