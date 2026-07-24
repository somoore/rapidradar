import unittest

from scripts.check_event_bus_policy import list_values


class ListValuesTest(unittest.TestCase):
    def test_indented_block_list(self) -> None:
        lines = [
            "      source:",
            "        - aws.ec2",
            "        - aws.s3",
        ]
        self.assertEqual(list_values(lines, "source"), {"aws.ec2", "aws.s3"})

    def test_indentationless_block_list(self) -> None:
        lines = [
            "      source:",
            "      - aws.guardduty",
        ]
        self.assertEqual(list_values(lines, "source"), {"aws.guardduty"})

    def test_flow_list_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported inline value"):
            list_values(["      source: [aws.newservice]"], "source")

    def test_inline_scalar_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported inline value"):
            list_values(["      source: aws.newservice"], "source")


if __name__ == "__main__":
    unittest.main()
