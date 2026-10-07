import json
import tempfile
import unittest
from pathlib import Path

from sentinelpass.analyzer import analyze_password, load_policy


class AnalyzerTests(unittest.TestCase):
    def test_empty_password_is_weak(self):
        result = analyze_password("")
        self.assertEqual(result["category"], "Weak")
        self.assertEqual(result["score"], 0)

    def test_common_password_is_flagged(self):
        result = analyze_password("password123")
        self.assertFalse(result["checks"]["not_common"])
        self.assertTrue(any("common password" in item.lower() for item in result["findings"]))

    def test_long_mixed_password_has_all_character_classes(self):
        result = analyze_password("N4v!gation-River-Cobalt-72")
        self.assertTrue(result["checks"]["lowercase"])
        self.assertTrue(result["checks"]["uppercase"])
        self.assertTrue(result["checks"]["digit"])
        self.assertTrue(result["checks"]["symbol"])
        self.assertGreaterEqual(result["length"], 16)

    def test_sequence_is_detected(self):
        result = analyze_password("Abc!9LongPassword")
        self.assertFalse(result["checks"]["no_obvious_sequence"])

    def test_repeated_run_is_detected(self):
        result = analyze_password("GoodPass!1111Long")
        self.assertFalse(result["checks"]["no_long_repeated_run"])

    def test_report_never_contains_password(self):
        secret = "MyPrivateExample!932"
        result = analyze_password(secret)
        self.assertNotIn(secret, json.dumps(result))

    def test_policy_can_be_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            policy = {
                "minimum_length": 8,
                "recommended_length": 10,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_digit": True,
                "require_symbol": True,
                "max_repeated_run": 3,
                "score_thresholds": {"moderate": 40, "strong": 70},
            }
            path.write_text(json.dumps(policy), encoding="utf-8")
            loaded = load_policy(path)
            result = analyze_password("Short!9x", loaded)
            self.assertTrue(result["checks"]["minimum_length"])
            self.assertFalse(result["checks"]["recommended_length"])

    def test_invalid_thresholds_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            policy = {
                "minimum_length": 12,
                "recommended_length": 16,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_digit": True,
                "require_symbol": True,
                "max_repeated_run": 3,
                "score_thresholds": {"moderate": 80, "strong": 70},
            }
            path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_policy(path)


if __name__ == "__main__":
    unittest.main()
