import unittest

from persistguard.baseline import compare_items


class BaselineTests(unittest.TestCase):
    def test_added_removed_changed(self):
        before = [{"id": "a", "label": "A", "score": 0}, {"id": "b", "label": "B", "score": 10}]
        after = [{"id": "a", "label": "A", "score": 40}, {"id": "c", "label": "C", "score": 60}]
        diff = compare_items(before, after)
        self.assertEqual(diff["summary"]["added"], 1)
        self.assertEqual(diff["summary"]["removed"], 1)
        self.assertEqual(diff["summary"]["changed"], 1)


if __name__ == "__main__":
    unittest.main()
