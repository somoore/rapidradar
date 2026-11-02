"""Output escaping for alert messages.

Alert text embeds values that are controlled by AWS resource metadata (resource ids, names, tag
keys and values, IAM user names, user agents, ...). An attacker who can create a resource in a
child account can therefore choose part of the text that RapidRadar sends to Slack, e-mail,
Google Chat and Teams.

* ``escape_html`` must be used for every value interpolated into an SES HTML body/attribute.
* ``escape_mrkdwn`` must be used for every value interpolated into Slack mrkdwn text, where
  ``<``/``>`` build links and ``<!channel>`` builds mention directives.

Both helpers are intentionally lossless for ordinary identifiers (``i-0abc``, ``arn:...``,
``user@example.com``) so existing message formatting is unchanged.
"""
from functools import wraps
from html import escape


def escape_html(value):
    """Escape a dynamic value for use in HTML text or an HTML attribute."""
    return escape(str(value), quote=True)


def escape_mrkdwn(value):
    """Escape a dynamic value for use in Slack mrkdwn.

    Slack decodes ``&amp;``/``&lt;``/``&gt;`` back to the literal characters, and the escaped forms
    cannot start a link (``<...>``) or a special mention (``<!channel>``).
    """
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _escape_string_args(escaper, func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        escaped_args = tuple(escaper(arg) if isinstance(arg, str) else arg for arg in args)
        escaped_kwargs = {key: escaper(value) if isinstance(value, str) else value
                          for key, value in kwargs.items()}
        return func(*escaped_args, **escaped_kwargs)
    return wrapper


def escape_html_args(func):
    """Decorator: HTML-escape every string argument of a message builder."""
    return _escape_string_args(escape_html, func)


def escape_mrkdwn_args(func):
    """Decorator: mrkdwn-escape every string argument of a message builder."""
    return _escape_string_args(escape_mrkdwn, func)


def harden_message_methods(cls, decorator, skip=("send_email",)):
    """Apply ``decorator`` to every public method of a message-builder class.

    The methods only add markup internally, so escaping all of their string arguments is safe and
    means a new message builder is escaped by default instead of by reviewer diligence.
    """
    for name in dir(cls):
        if name.startswith("_") or name in skip:
            continue
        method = getattr(cls, name)
        if callable(method):
            setattr(cls, name, decorator(method))
    return cls
