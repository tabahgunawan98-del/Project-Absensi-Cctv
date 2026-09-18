from dataclasses import dataclass
from typing import Optional

@dataclass
class QualityResult:
    is_good: bool
    reason: Optional[str] = None

class QualityGate:
    def check(self, image_data: bytes) -> QualityResult:
        if b"blur" in image_data:
            return QualityResult(False, "blurred")
        if b"low_light" in image_data:
            return QualityResult(False, "low_light")
        if b"occluded" in image_data:
            return QualityResult(False, "occluded")
        return QualityResult(True)
