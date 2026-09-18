from dataclasses import dataclass
from typing import List, Optional

@dataclass
class BoundingBox:
    x1: int
    y1: int
    x2: int
    y2: int

@dataclass
class Detection:
    bbox: BoundingBox
    score: float

class PersonDetector:
    def detect(self, image_data: bytes) -> List[Detection]:
        # Synthetic: empty data or specific markers trigger detection
        if not image_data:
            return []
        if b"person" in image_data:
            return [Detection(BoundingBox(10, 10, 100, 100), 0.95)]
        return []
