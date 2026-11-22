import unittest

from research.linux_isolated_worker_v1.pilot import EXPECTED_BEARER, admit


class LinuxPilotPortableTests(unittest.TestCase):
    def setUp(self):
        self.request = {"schema": "guardian.linux-worker-request.v1", "origin": "synthetic", "action": "synthetic_echo", "payload": "safe"}

    def test_exact_synthetic_admission(self):
        self.assertEqual(admit(EXPECTED_BEARER, self.request), {"admitted": True, "reason": "SYNTHETIC_BEARER_AND_SCOPE"})

    def test_wrong_bearer_refused(self):
        self.assertEqual(admit("wrong", self.request), {"admitted": False, "reason": "BEARER_REFUSED"})

    def test_request_scope_refused(self):
        self.assertEqual(admit(EXPECTED_BEARER, dict(self.request, action="shell")), {"admitted": False, "reason": "REQUEST_SCOPE"})

    def test_extra_field_refused(self):
        self.assertEqual(admit(EXPECTED_BEARER, {**self.request, "authorized": True}), {"admitted": False, "reason": "REQUEST_SHAPE"})


if __name__ == "__main__":
    unittest.main()

