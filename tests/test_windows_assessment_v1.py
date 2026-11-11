import unittest

from tools.windows_assessment_v1 import campaign_control_causes, classify_startup


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

    def test_broken_campaign_controls_are_not_refutations(self):
        self.assertEqual(campaign_control_causes([], [{"control_broken": "startup"}]),
                         ["V02_CAMPAIGN_CONTROL_BROKEN", "V04_CAMPAIGN_CONTROL_BROKEN"])
        self.assertEqual(campaign_control_causes([{"name": "control", "passed": True}], [{"passed": True}]), [])


if __name__ == "__main__":
    unittest.main()

