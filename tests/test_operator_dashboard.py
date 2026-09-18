import unittest

from frontend.dashboard import (
    DashboardApiError,
    DashboardClient,
    OperatorDashboard,
    SyntheticDashboardApi,
)


class OperatorDashboardTest(unittest.TestCase):
    def setUp(self):
        self.api = SyntheticDashboardApi()
        self.dashboard = OperatorDashboard(self.api, actor="operator-1", roles={"operator"})

    def test_render_shows_attendance_unknown_review_health_without_sensitive_data(self):
        html = self.dashboard.render()
        self.assertIn("Operator attendance dashboard", html)
        self.assertIn("EMP-001", html)
        self.assertIn("unknown", html)
        self.assertIn("review_required", html)
        self.assertIn("Queue: 2 pending", html)
        self.assertIn("Health: ready", html)
        for sensitive in ("embedding", "template", "token", "image", "face_vector", "secret-token"):
            self.assertNotIn(sensitive, html.lower())

    def test_filters_date_timezone_site_and_status(self):
        html = self.dashboard.render(filters={
            "date": "2026-09-18",
            "timezone": "Asia/Jakarta",
            "site_id": "site-a",
            "status": "review_required",
        })
        self.assertIn("Timezone: Asia/Jakarta", html)
        self.assertIn("site-a", html)
        self.assertIn("review-1", html)
        self.assertNotIn("att-1", html)
        self.assertNotIn("unknown-1", html)

    def test_review_confirmation_requires_reason_and_writes_audit(self):
        with self.assertRaisesRegex(ValueError, "reason required"):
            self.dashboard.review("review-1", "approve", employee_id="EMP-002", reason="")
        result = self.dashboard.review("review-1", "approve", employee_id="EMP-002", reason="Badge verified")
        self.assertEqual(result["status"], "resolved")
        html = self.dashboard.render()
        self.assertIn("human_review approve", html)
        self.assertIn("Badge verified", html)
        self.assertIn("operator-1", html)

    def test_review_reject_and_correct_are_explicit_and_never_payroll(self):
        reject = self.dashboard.review("unknown-1", "reject", reason="Visitor, not employee")
        correct = self.dashboard.correct_attendance("att-1", employee_id="EMP-003", reason="Manual badge correction")
        self.assertEqual((reject["status"], correct["status"]), ("resolved", "corrected"))
        html = self.dashboard.render()
        self.assertIn("human_review reject", html)
        self.assertIn("manual_correction", html)
        self.assertIn("No payroll or sanctions are automated", html)
        self.assertNotIn("payroll_applied", html)
        self.assertNotIn("penalty", html)

    def test_forbidden_state_blocks_action_but_backend_remains_authoritative(self):
        viewer = OperatorDashboard(self.api, actor="viewer-1", roles={"viewer"})
        html = viewer.render()
        self.assertIn("Review controls unavailable", html)
        with self.assertRaises(PermissionError):
            viewer.review("review-1", "approve", employee_id="EMP-002", reason="Badge verified")

    def test_unknown_is_not_auto_matched(self):
        with self.assertRaisesRegex(ValueError, "employee_id required"):
            self.dashboard.review("unknown-1", "approve", reason="No match available")
        html = self.dashboard.render()
        self.assertIn("unknown-1", html)
        self.assertIn("No employee selected", html)
        self.assertNotIn("attendance_created_from_unknown", html)

    def test_dedupe_and_non_biometric_source_badges_render(self):
        html = self.dashboard.render()
        self.assertIn("Duplicate window", html)
        self.assertIn("Badge", html)
        self.assertIn("QR", html)
        self.assertIn("Manual", html)

    def test_loading_empty_error_and_retry_states(self):
        self.api.fail_next("temporary queue outage")
        html = self.dashboard.render()
        self.assertIn("role=\"alert\"", html)
        self.assertIn("temporary queue outage", html)
        self.assertIn("Retry", html)
        self.assertEqual(self.api.fetch_count, 2)

        empty = OperatorDashboard(SyntheticDashboardApi(empty=True), actor="operator-1", roles={"operator"})
        empty_html = empty.render()
        self.assertIn("No attendance events match", empty_html)
        self.assertIn("aria-busy=\"false\"", empty_html)

    def test_keyboard_accessible_labels_and_form_errors(self):
        html = self.dashboard.render()
        self.assertIn("<label for=\"filter-date\">Tanggal</label>", html)
        self.assertIn("tabindex=\"0\"", html)
        self.assertIn("aria-describedby=\"review-unknown-1-reason-error\"", html)
        self.assertIn("role=\"status\"", html)

    def test_backend_mock_enforces_authorization_on_direct_calls(self):
        with self.assertRaises(PermissionError):
            self.api.review(
                "review-1",
                "approve",
                employee_id="EMP-002",
                actor="viewer-1",
                actor_roles={"viewer"},
                reason="Badge verified",
            )
        result = self.api.review(
            "review-1",
            "approve",
            employee_id="EMP-002",
            actor="operator-1",
            actor_roles={"operator"},
            reason="Badge verified",
        )
        self.assertEqual(result["status"], "resolved")

    def test_correction_paths_require_valid_employee_identity(self):
        for employee_id in (None, "", "   "):
            with self.assertRaisesRegex(ValueError, "employee_id required"):
                self.dashboard.review("unknown-1", "correct", employee_id=employee_id, reason="Selected identity")
            with self.assertRaisesRegex(ValueError, "employee_id required"):
                self.dashboard.correct_attendance("att-1", employee_id=employee_id, reason="Manual correction")
        result = self.dashboard.review("unknown-1", "correct", employee_id="EMP-009", reason="Badge checked")
        self.assertEqual(result["status"], "resolved")

    def test_audit_and_stored_rows_are_redacted_copied_and_append_only(self):
        source_attendance = [{
            "id": "att-x",
            "employee_id": "EMP-010",
            "site_id": "site-a",
            "occurred_at": "2026-09-18T00:30:00Z",
            "status": "matched",
            "kind": "check_in",
            "source": "badge",
            "payload": {"token": "secret"},
            "image": "raw-image",
            "embedding": [1, 2, 3],
        }]
        source_audit = [{
            "actor": "seed",
            "action": "seed",
            "reason": "ok",
            "details": {"notes": ["original"]},
            "token": "secret",
        }]
        client = DashboardClient(
            attendance=source_attendance,
            reviews=[],
            health={"status": "ready"},
            queue={"pending": 0},
            audit=source_audit,
            authorized_roles={"operator"},
        )
        source_attendance[0]["employee_id"] = "MUTATED"
        source_audit[0]["reason"] = "MUTATED"
        source_audit[0]["details"]["notes"].append("CALLER-MUTATED")
        rendered = OperatorDashboard(client, actor="operator-1", roles={"operator"}).render()
        self.assertIn("EMP-010", rendered)
        self.assertNotIn("MUTATED", rendered)
        self.assertNotIn("CALLER-MUTATED", rendered)
        self.assertNotIn("secret", repr(client).lower())
        self.assertNotIn("embedding", repr(client).lower())
        with self.assertRaises(AttributeError):
            client.audit.append({"action": "tamper"})

    def test_audit_property_does_not_expose_mutable_storage(self):
        client = DashboardClient(
            attendance=[],
            reviews=[],
            health={"status": "ready"},
            queue={"pending": 0},
            audit=[{"actor": "seed", "action": "seed", "reason": "ok", "details": {"notes": ["original"]}}],
            authorized_roles={"operator"},
        )
        exposed = client.audit
        exposed[0]["action"] = "direct-tamper"
        exposed[0]["details"]["notes"].append("nested-tamper")
        fetched = client.fetch_dashboard()
        rendered = OperatorDashboard(client, actor="operator-1", roles={"operator"}).render()
        self.assertEqual(fetched["audit"][0]["action"], "seed")
        self.assertEqual(fetched["audit"][0]["details"]["notes"], ["original"])
        self.assertIn("seed", rendered)
        self.assertNotIn("direct-tamper", rendered)
        self.assertNotIn("nested-tamper", rendered)

    def test_date_filter_uses_selected_timezone_midnight_and_dst_boundaries(self):
        client = DashboardClient(
            attendance=[
                {
                    "id": "jakarta-midnight",
                    "employee_id": "EMP-011",
                    "site_id": "site-a",
                    "occurred_at": "2026-03-29T17:30:00Z",
                    "status": "matched",
                    "kind": "check_in",
                    "source": "badge",
                },
                {
                    "id": "ny-dst-boundary",
                    "employee_id": "EMP-012",
                    "site_id": "site-a",
                    "occurred_at": "2026-03-08T04:30:00Z",
                    "status": "matched",
                    "kind": "check_in",
                    "source": "qr",
                },
            ],
            reviews=[],
            health={"status": "ready"},
            queue={"pending": 0},
            authorized_roles={"operator"},
        )
        dashboard = OperatorDashboard(client, actor="operator-1", roles={"operator"})
        jakarta = dashboard.render(filters={"date": "2026-03-30", "timezone": "Asia/Jakarta"})
        new_york = dashboard.render(filters={"date": "2026-03-07", "timezone": "America/New_York"})
        self.assertIn("jakarta-midnight", jakarta)
        self.assertNotIn("ny-dst-boundary", jakarta)
        self.assertIn("ny-dst-boundary", new_york)
        self.assertNotIn("jakarta-midnight", new_york)

    def test_review_controls_employee_selector_and_unique_a11y_ids_render(self):
        html = self.dashboard.render()
        for action in ("approve", "reject", "correct"):
            self.assertIn(f'value=\"{action}\"', html)
        self.assertIn("select id=\"review-unknown-1-employee\"", html)
        self.assertIn("for=\"review-review-1-reason\"", html)
        self.assertEqual(html.count("id=\"review-reason\""), 0)
        self.assertEqual(html.count("id=\"review-unknown-1-reason\""), 1)
        self.assertEqual(html.count("id=\"review-review-1-reason\""), 1)
        self.assertIn("role=\"group\"", html)

    def test_final_render_state_is_not_busy(self):
        html = self.dashboard.render()
        self.assertNotIn("aria-busy=\"true\"", html)
        self.assertIn("aria-busy=\"false\"", html)
        self.assertIn("aria-busy=\"true\"", self.dashboard.render(loading=True))


if __name__ == "__main__":
    unittest.main()
