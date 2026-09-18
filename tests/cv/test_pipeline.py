import unittest
import time
from src.cv.pipeline import CVPipeline

class TestCVPipeline(unittest.TestCase):
    def setUp(self):
        self.registry = {
            "emp_001": [1.0, 0.0, 0.0],
            "emp_002": [0.0, 1.0, 0.0]
        }
        self.pipeline = CVPipeline(self.registry)

    def test_detection_and_match_success(self):
        # person + employee_1 marker
        data = b"person with employee_1 marker"
        result = self.pipeline.process(data)
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["employee_id"], "emp_001")
        self.assertGreaterEqual(result["score"], 0.7)

    def test_unmarked_outsider_is_deterministic_unknown_for_1000_runs(self):
        results = [self.pipeline.process(b"person outsider") for _ in range(1000)]

        self.assertEqual({result["status"] for result in results}, {"unknown"})
        self.assertEqual({result["reason"] for result in results}, {"embedding_unavailable"})
        self.assertNotIn("employee_id", results[0])

    def test_equal_candidates_require_review(self):
        self.pipeline.extractor.extract = lambda *_: [1.0, 1.0, 0.0]

        result = self.pipeline.process(b"person candidate")

        self.assertEqual(result["status"], "review_required")
        self.assertEqual(result["reason"], "ambiguous_candidates")

    def test_near_tie_respects_configured_margin_boundary(self):
        self.pipeline.matcher.ambiguity_margin = 0.05
        self.pipeline.extractor.extract = lambda *_: [1.0, 0.95, 0.0]
        near_tie = self.pipeline.process(b"person candidate")
        self.pipeline.extractor.extract = lambda *_: [1.0, 0.9, 0.0]
        clear_winner = self.pipeline.process(b"person candidate")

        self.assertEqual(near_tie["status"], "review_required")
        self.assertEqual(near_tie["reason"], "ambiguous_candidates")
        self.assertEqual(clear_winner["status"], "matched")
        self.assertEqual(clear_winner["employee_id"], "emp_001")

    def test_malformed_inputs_fail_closed(self):
        for malformed in (None, "person employee_1", b""):
            with self.subTest(malformed=malformed):
                result = self.pipeline.process(malformed)
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["reason"], "malformed_input")
                self.assertNotIn("employee_id", result)

    def test_no_person_detected(self):
        data = b"empty room"
        result = self.pipeline.process(data)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "no_person_detected")

    def test_quality_gate_blur(self):
        data = b"person blur"
        result = self.pipeline.process(data)
        self.assertEqual(result["status"], "review_required")
        self.assertEqual(result["reason"], "blurred")

    def test_quality_gate_low_light(self):
        data = b"person low_light"
        result = self.pipeline.process(data)
        self.assertEqual(result["status"], "review_required")
        self.assertEqual(result["reason"], "low_light")

    def test_spoof_detection(self):
        data = b"person spoof"
        result = self.pipeline.process(data)
        self.assertEqual(result["status"], "review_required")
        self.assertEqual(result["reason"], "spoof_suspected")

    def test_corrupt_empty_file(self):
        result = self.pipeline.process(b"")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "malformed_input")

    def test_latency_p95(self):
        latencies = []
        for _ in range(100):
            data = b"person employee_1"
            res = self.pipeline.process(data)
            latencies.append(res["latency_ms"])

        p95 = sorted(latencies)[94]
        print(f"\nP95 Latency: {p95:.2f}ms")
        self.assertLess(p95, 10.0) # Mock should be fast

if __name__ == "__main__":
    unittest.main()
