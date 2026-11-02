"""Validation of the account carried by an inbound CloudTrail/EventBridge envelope.

The central event bus policy allows any principal in the organization to publish, so the account
inside an event cannot be trusted until it is checked against the event's own CloudTrail identity
and against the configured deployment targets. This runs before any ``sts:AssumeRole`` call.
"""


def validate_event_account(event, management_account_id, deployment_target_accounts):
    """Return ``None`` when the event account is trustworthy, otherwise a rejection reason.

    ``deployment_target_accounts`` is the account-id keyed mapping built from the
    ``DEPLOYMENT_TARGET_ACCOUNTS`` secret.
    """
    account_id = event.get('recipientAccountId') or event.get('account') or event.get('accountId')
    detail = event.get('detail') or {}
    identity_account_id = (detail.get('userIdentity') or {}).get('accountId')

    if account_id and identity_account_id and account_id != identity_account_id:
        return (
            f"envelope account {account_id} does not match "
            f"detail.userIdentity.accountId {identity_account_id}"
        )

    if account_id and account_id != management_account_id and account_id not in deployment_target_accounts:
        return f"account {account_id} is not a configured deployment target"

    return None
