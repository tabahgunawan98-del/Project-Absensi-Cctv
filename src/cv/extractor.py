from typing import Any, List, Optional


class FeatureExtractor:
    def extract(self, image_data: bytes, bbox: Any) -> Optional[List[float]]:
        # Synthetic markers stand in for an authorized embedding model.
        if b"employee_1" in image_data:
            return [1.0, 0.0, 0.0]
        if b"employee_2" in image_data:
            return [0.0, 1.0, 0.0]
        if b"unknown" in image_data:
            return [0.0, 0.0, 1.0]
        return None
