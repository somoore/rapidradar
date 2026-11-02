import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from messenger.sanitize import (  # noqa: E402
    escape_html,
    escape_html_args,
    escape_mrkdwn,
    escape_mrkdwn_args,
    harden_message_methods,
)


class EscapeHtmlTest(unittest.TestCase):
    def test_script_tag_is_neutralised(self):
        self.assertEqual(
            escape_html('<img src=x onerror="alert(1)">'),
            "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;",
        )

    def test_quotes_are_escaped_for_attributes(self):
        self.assertNotIn("'", escape_html("x' onmouseover='y"))

    def test_plain_identifiers_are_unchanged(self):
        for value in ("i-0abc", "arn:aws:s3:::bucket", "user@example.com", "k=v"):
            self.assertEqual(escape_html(value), value)


class EscapeMrkdwnTest(unittest.TestCase):
    def test_channel_mention_cannot_be_injected(self):
        self.assertNotIn("<!channel>", escape_mrkdwn("<https://evil|<!channel>>"))

    def test_markup_characters_are_escaped(self):
        self.assertEqual(escape_mrkdwn("a<b>c&d"), "a&lt;b&gt;c&amp;d")

    def test_plain_identifiers_are_unchanged(self):
        self.assertEqual(escape_mrkdwn("i-0abc"), "i-0abc")


class ArgumentEscapingTest(unittest.TestCase):
    def test_html_decorator_escapes_positional_and_keyword_strings(self):
        class Builder:
            @escape_html_args
            def message(self, text, title=None):
                return f"{text}|{title}"

        self.assertEqual(Builder().message("<a>", title="<b>"), "&lt;a&gt;|&lt;b&gt;")

    def test_mrkdwn_decorator_escapes_positional_and_keyword_strings(self):
        class Builder:
            @escape_mrkdwn_args
            def message(self, text, title=None):
                return f"{text}|{title}"

        self.assertEqual(Builder().message("<!channel>", title="<b>"), "&lt;!channel&gt;|&lt;b&gt;")

    def test_non_string_arguments_are_left_alone(self):
        class Builder:
            @escape_html_args
            def message(self, tags, count):
                return tags, count

        tags, count = Builder().message(["<a>"], 3)
        self.assertEqual(tags, ["<a>"])
        self.assertEqual(count, 3)

    def test_harden_message_methods_skips_private_and_excluded_methods(self):
        class Builder:
            def public(self, text):
                return text

            def send_email(self, text):
                return text

            def _private(self, text):
                return text

        harden_message_methods(Builder, escape_html_args)
        self.assertEqual(Builder().public("<a>"), "&lt;a&gt;")
        self.assertEqual(Builder().send_email("<a>"), "<a>")
        self.assertEqual(Builder()._private("<a>"), "<a>")


if __name__ == "__main__":
    unittest.main()
