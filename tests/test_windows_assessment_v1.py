import unittest

from tools.windows_assessment_v1 import classify_startup


class WindowsAssessmentPortable(unittest.TestCase):
    def test_verified_requires_observed_start(self):
        self.assertEqual(classify_startup({"attempts": [{"exit_code": 0}]})["status"], "VERIFIED")

    def test_lpc_reply_stall_remains_not_covered(self):
        record = {"attempts": [{"wait": 258, "exit_code": 259, "thread_query": {"stdout": '{"WaitReason": 10}'}}]}
        result = classify_startup(record)
        self.assertEqual(result["status"], "NOT_COVERED")
        self.assertEqual(result["root_cause"], "CREATEPROCESSWITHTOKEN_CHILD_STALLED_IN_LPC_REPLY")

    def test_unknown_failure_not_promoted(self):
        self.assertEqual(classify_startup({"attempts": []})["status"], "NOT_COVERED")


if __name__ == "__main__":
    unittest.main()

