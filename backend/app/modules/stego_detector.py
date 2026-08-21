import os
import logging
import numpy as np
from typing import List, Dict, Any
from backend.app.modules.base import BaseModule

logger = logging.getLogger("stego_detector")

# Safe dummy marker we look for in tests
STEGO_DEMO_MARKER = "STEGO_DEMO_MARKER_2026"

# Common binary headers to detect statically
MAGIC_HEADERS = {
    b"MZ": "Windows Portable Executable (PE) Magic Header",
    b"\x7fELF": "Linux ELF Executable Magic Header",
    b"PK\x03\x04": "ZIP/Archive Container Header"
}

class StegoDetector(BaseModule):
    @property
    def name(self) -> str:
        return "stego_detector"

    def scan(self, filepath: str, format: str) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(filepath):
            return findings

        if format == 'ONNX':
            findings.extend(self._scan_onnx(filepath))
        elif format == 'SAFETENSORS':
            findings.extend(self._scan_safetensors(filepath))
        elif format == 'PYTORCH':
            # Skip since we do not load weights of pickle models for safety
            pass
            
        return findings

    def _analyze_tensor_stego(self, weights: np.ndarray, name: str) -> List[Dict[str, Any]]:
        findings = []
        
        # Only analyze float32 weights where LSB modifications are feasible
        if weights.dtype != np.float32:
            return findings
            
        flat_weights = weights.flatten()
        if len(flat_weights) < 64:
            return findings  # Too small to perform statistical stego check

        try:
            # View-cast float32 to uint32 to extract raw bits
            uint_weights = flat_weights.view(np.uint32)
            lsbs = uint_weights & 1
            
            # 1. Compute Shannon Entropy of LSBs
            total_bits = len(lsbs)
            ones_count = int(np.sum(lsbs))
            zeros_count = total_bits - ones_count
            
            p0 = zeros_count / total_bits
            p1 = ones_count / total_bits
            
            entropy = 0.0
            if p0 > 0:
                entropy -= p0 * np.log2(p0)
            if p1 > 0:
                entropy -= p1 * np.log2(p1)

            # 2. Extract bytes from LSBs
            # Group bits into 8-bit bytes
            byte_list = []
            for i in range(0, min(total_bits, 8000), 8):  # Limit scan range to avoid overhead
                if i + 8 > total_bits:
                    break
                byte_val = 0
                for bit_pos in range(8):
                    byte_val |= (int(lsbs[i + bit_pos]) << bit_pos)
                byte_list.append(byte_val)
                
            reconstructed_bytes = bytes(byte_list)
            
            # Check if our target test marker is in the extracted bytes
            decoded_text = ""
            try:
                # Decoded text ignoring non-ascii characters
                decoded_text = reconstructed_bytes.decode('ascii', errors='ignore')
            except Exception:
                pass

            # A. Check for demo stego marker
            if STEGO_DEMO_MARKER in decoded_text:
                findings.append({
                    "severity": "CRITICAL",
                    "module": self.name,
                    "title": "Steganographic Marker Detected",
                    "description": (
                        f"Layer '{name}' contains the synthetic demonstration steganography marker "
                        f"'{STEGO_DEMO_MARKER}' hidden in its weight least significant bits (LSBs)."
                    ),
                    "layer_name": name,
                    "evidence": {
                        "marker_found": STEGO_DEMO_MARKER,
                        "lsb_entropy": round(entropy, 4),
                        "extracted_prefix": decoded_text[:50]
                    }
                })
                return findings  # If marker is found, it is definite, no need for statistical guesses

            # B. Check for suspicious magic file signatures
            for magic, file_type in MAGIC_HEADERS.items():
                if magic in reconstructed_bytes:
                    findings.append({
                        "severity": "CRITICAL",
                        "module": self.name,
                        "title": "Embedded File Header Detected in LSBs",
                        "description": (
                            f"Layer '{name}' contains a hidden byte pattern matching the {file_type} "
                            f"signature inside its weight least significant bits. This suggests a potential payload injection."
                        ),
                        "layer_name": name,
                        "evidence": {
                            "detected_header": file_type,
                            "matching_bytes": magic.hex(),
                            "lsb_entropy": round(entropy, 4)
                        }
                    })
                    return findings

            # C. Check for statistical anomalies (e.g. extremely uniform random LSBs)
            # Standard neural net weights have natural variations, but when overwritten with compressed/encrypted data,
            # LSB entropy gets extremely close to 1.0, and bit balance is almost exactly 50/50.
            # In natural nets, LSBs can be random, so we only flag as INFO/LOW if no direct signature matches.
            if len(flat_weights) >= 512 and 0.999 <= entropy <= 1.0:
                findings.append({
                    "severity": "LOW",
                    "module": self.name,
                    "title": "Highly Uniform LSB Entropy",
                    "description": (
                        f"Layer '{name}' has an LSB Shannon entropy of {entropy:.5f} with a near-perfect "
                        f"distribution of bits ({ones_count} ones, {zeros_count} zeros). This matches the statistical profile "
                        f"of encrypted or compressed data injected into weights."
                    ),
                    "layer_name": name,
                    "evidence": {
                        "lsb_entropy": round(entropy, 5),
                        "ones_count": ones_count,
                        "zeros_count": zeros_count,
                        "total_bits": total_bits
                    }
                })

        except Exception as e:
            logger.warning(f"Failed to analyze LSB stego on layer {name}: {e}")

        return findings

    def _scan_onnx(self, filepath: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            import onnx
            from onnx import numpy_helper
            
            model = onnx.load(filepath)
            for initializer in model.graph.initializer:
                try:
                    weights = numpy_helper.to_array(initializer)
                    findings.extend(self._analyze_tensor_stego(weights, initializer.name))
                except Exception as e:
                    logger.warning(f"Error parsing tensor {initializer.name} in ONNX: {e}")
        except Exception as e:
            logger.debug(f"Stego scan failed to parse ONNX: {e}")
        return findings

    def _scan_safetensors(self, filepath: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            from safetensors import safe_open
            with safe_open(filepath, framework="numpy", device="cpu") as f:
                for name in f.keys():
                    try:
                        weights = f.get_tensor(name)
                        findings.extend(self._analyze_tensor_stego(weights, name))
                    except Exception as e:
                        logger.warning(f"Error extracting tensor {name} in Safetensors: {e}")
        except Exception as e:
            logger.debug(f"Stego scan failed to parse Safetensors: {e}")
        return findings
