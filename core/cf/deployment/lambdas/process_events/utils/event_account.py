"""Validation of the account carried by an inbound CloudTrail/EventBridge envelope.

The central event bus policy allows any principal in the organization to publish, so the account
an event is attributed to cannot be trusted until it is checked against the configured deployment
targets. This runs before any ``sts:AssumeRole`` call.

Only the envelope account (the account that recorded the event and owns the affected resource,
which is also the account ``AWSHelper`` assumes into) is validated. ``detail.userIdentity.accountId``
is deliberately not required to match: CloudTrail records cross-account access with the caller's
account there, and such events (for example an external account changing a monitored bucket's ACL)
are exactly what the detectors must still see. That field is part of the publisher-controlled
``detail`` payload, so comparing it would not add any assurance either.
"""


def validate_event_account(event, management_account_id, deployment_target_accounts):
    """Return ``None`` when the event account is trustworthy, otherwise a rejection reason.

    ``deployment_target_accounts`` is the account-id keyed mapping built from the
    ``DEPLOYMENT_TARGET_ACCOUNTS`` secret.
    """
    account_id = event.get('recipientAccountId') or event.get('account') or event.get('accountId')

    if account_id and account_id != management_account_id and account_id not in deployment_target_accounts:
        return f"account {account_id} is not a configured deployment target"

    return None
