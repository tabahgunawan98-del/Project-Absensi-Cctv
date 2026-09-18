import time
from typing import Dict, Any
from .detector import PersonDetector
from .extractor import FeatureExtractor
from .matcher import IdentityMatcher
from .quality import QualityGate
from .spoofing import SpoofingMitigation

class CVPipeline:
    def __init__(self, registry: Dict[str, Any]):
        self.detector = PersonDetector()
        self.extractor = FeatureExtractor()
        self.matcher = IdentityMatcher(registry)
        self.quality = QualityGate()
        self.spoofing = SpoofingMitigation()

    def process(self, image_data: bytes) -> Dict[str, Any]:
        start_time = time.time()
        if not isinstance(image_data, bytes) or not image_data:
            return {
                "status": "unknown",
                "reason": "malformed_input",
                "latency_ms": (time.time() - start_time) * 1000,
            }

        # 1. Quality Check
        quality = self.quality.check(image_data)
        if not quality.is_good:
            return {
                "status": "review_required",
                "reason": quality.reason,
                "latency_ms": (time.time() - start_time) * 1000
            }

        # 2. Anti-spoofing
        if self.spoofing.is_spoof(image_data):
            return {
                "status": "review_required",
                "reason": "spoof_suspected",
                "latency_ms": (time.time() - start_time) * 1000
            }

        # 3. Detection
        detections = self.detector.detect(image_data)
        if not detections:
            return {
                "status": "unknown",
                "reason": "no_person_detected",
                "latency_ms": (time.time() - start_time) * 1000
            }

        # 4. Extraction & Matching (Simplified: use first detection)
        det = detections[0]
        embedding = self.extractor.extract(image_data, det.bbox)
        if embedding is None:
            return {
                "status": "unknown",
                "reason": "embedding_unavailable",
                "latency_ms": (time.time() - start_time) * 1000,
            }
        emp_id, score = self.matcher.match(embedding)

        latency_ms = (time.time() - start_time) * 1000

        if emp_id:
            return {
                "status": "matched",
                "employee_id": emp_id,
                "score": score,
                "latency_ms": latency_ms
            }

        # Ambiguous check (if score is above a lower threshold but below match threshold)
        if score > 0.5:
            return {
                "status": "review_required",
                "reason": "ambiguous_candidates",
                "score": score,
                "latency_ms": latency_ms
            }

        return {
            "status": "unknown",
            "reason": "below_threshold",
            "score": score,
            "latency_ms": latency_ms
        }
