import math
from typing import Dict, List, Optional, Tuple

class IdentityMatcher:
    def __init__(
        self,
        registry: Dict[str, List[float]],
        threshold: float = 0.7,
        ambiguity_margin: float = 0.05,
    ):
        self.registry = registry
        self.threshold = threshold
        self.ambiguity_margin = ambiguity_margin

    def _cosine_similarity(self, v1: List[float], v2: List[float]) -> float:
        dot_product = sum(a * b for a, b in zip(v1, v2))
        norm1 = math.sqrt(sum(a * a for a in v1))
        norm2 = math.sqrt(sum(b * b for b in v2))
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return dot_product / (norm1 * norm2)

    def match(self, embedding: List[float]) -> Tuple[Optional[str], float]:
        candidates = sorted(
            (
                (self._cosine_similarity(embedding, employee_embedding), employee_id)
                for employee_id, employee_embedding in self.registry.items()
            ),
            reverse=True,
        )
        if not candidates:
            return None, -1.0

        best_score, best_match = candidates[0]
        if len(candidates) > 1:
            second_score = candidates[1][0]
            if best_score - second_score <= self.ambiguity_margin:
                return None, float(best_score)
        if best_score >= self.threshold:
            return best_match, float(best_score)
        return None, float(best_score)
