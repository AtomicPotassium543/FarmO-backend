import unittest

from bson import ObjectId

from routes.advice import format_advice

class AdviceFormattingTests(unittest.TestCase):
    def test_steps_are_validated_and_sorted_by_order(self):
        advice_id = ObjectId()
        advice = {
            "_id": advice_id,
            "steps": [
                {
                    "order": 2,
                    "title": "Second step",
                    "description": "Description",
                    "reason": "Reason",
                    "crops": ["corn"]
                },
                {
                    "order": 1,
                    "title": "First step",
                    "description": "Description",
                    "reason": "Reason",
                    "crops": ["corn"]
                }
            ]
        }

        formatted = format_advice(advice)

        self.assertEqual(
            [step["order"] for step in formatted["steps"]],
            [1, 2]
        )
        self.assertEqual(formatted["id"], str(advice_id))

    def test_missing_steps_are_returned_as_an_empty_list(self):
        formatted = format_advice({"_id": ObjectId()})

        self.assertEqual(formatted["steps"], [])


if __name__ == "__main__":
    unittest.main()
