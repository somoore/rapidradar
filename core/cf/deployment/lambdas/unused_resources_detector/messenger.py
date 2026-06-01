from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import datetime
import json
import requests
from httplib2 import Http
import pytz
import boto3
import utils

class CustomException(Exception):
    """ Custom Exception class inherited from Exception class """

class Messenger():
    def __init__(self, notification_app, webhooks, account_id, region, resource_type, is_delete):
        self.notification_app = notification_app
        self.webhooks = webhooks
        self.account_id = account_id
        self.region = region
        self.resource_type = resource_type
        self.is_delete = is_delete

        if notification_app == "slack":
            self.send_alert = self.__send_slack_message
        elif notification_app == "msteams":
            self.send_alert = self.__send_msteams_message
        elif notification_app == "googlechat":
            self.send_alert = self.__send_googlechat_message
        else:
            raise ValueError("Invalid format, must be ['slack', 'msteams', 'googlechat']")

    def __send_slack_message(self, user: str, resources: list, notified_at: str, current_date: str, is_launch_wizard: bool, step) -> bool:
        message_headers = {'Content-Type': 'application/json; charset=UTF-8'}
        http_obj = Http()
        hour_diff = 0
        message = {}

        resources = "\n".join([str(elem) for elem in resources])

        if self.resource_type == 'EC2Instance':
            if notified_at is not None:
                timezone_abbrev = utils.extract_timezone_abbreviation(notified_at)
                difference = datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.strptime(notified_at, f'%b %d, %Y %I:%M %p {timezone_abbrev}').replace(tzinfo=pytz.timezone('CST6CDT')).astimezone(pytz.utc)
                hour_diff = int(difference.total_seconds() / 3600)

            if step == 1 and not hour_diff:
                message = {
                    "blocks": [{
                        "type": "context",
                        "elements": [{
                                "type": "mrkdwn",
                                "text": f"""*Unused Resources Found in AWS [Initial Message]*
Our telemetry has indicated, @{user.split('@')[0]} has unused resources in Amazon Web Services. These are EC2 instances in a 'stopped' state.
Here are the resources created by *{user}*, including the AWS account, Region & timestamp:

{resources}

If these AWS resources are no longer being used, we kindly ask that you backup your data as/if needed and terminate the resource(s). If the resource is needed, please 'start' the resource and utilize.

Thank you!
"""
                        }]
                    }]
                }
            elif step == 2 and hour_diff >= 120:
                message = {
                    "blocks": [{
                        "type": "context",
                        "elements": [{
                                "type": "mrkdwn",
                                "text": f"""*Unused Resources Found in AWS [Pending Deletion]*
On {notified_at}, we sent you an alert about unused resources of User @{user.split('@')[0]} in AWS account. As of today {current_date}, the following resources that were sent in the previous alert have not been either 'terminated' or 'started' and are still in a 'stopped' state in Amazon Web Services:

{resources}

Again, If you are no longer using these AWS resources, we kindly ask that you backup your data as/if needed and terminate the resource(s). If the resource is needed, please 'start' the resource and utilize.
We are now tagging the unused resources with a 'pending deletion' tag. In 14 days these resource(s) will be terminated entirely. Please take action now, otherwise these resources will be automatically terminated.

Thank you!
"""
                        }]
                    }]
                }
            elif step == 3 and hour_diff >= 312:
                message = {
                    "blocks": [{
                        "type": "context",
                        "elements": [{
                                "type": "mrkdwn",
                                "text": f"""*Unused Resources Found in AWS [Final Reminder]*
This is our 3rd attempt to message about unused resources of User @{user.split('@')[0]} in AWS. In 24 hours these EC2 instances will be terminated:

{resources}

Again, If these AWS resources are no longer being used, we kindly ask that you backup your data as/if needed and terminate the resource(s). If the resource is needed, please 'start' the resource and utilize.

Thank you!
"""
                        }]
                    }]
                }
            elif step == 4 and hour_diff >= 24:
                message = {
                    "blocks": [{
                        "type": "context",
                        "elements": [{
                                "type": "mrkdwn",
                                "text": f"""*Unused Resources Found in AWS [TERMINATED]*
This is to inform you that unused EC2 instances of User @{user.split('@')[0]} in AWS have been terminated.
Prior to termination, we created an Amazon Machine Image (AMI) of the instance and tagged it with *Owner = {user}*. Including the AMI ID below for your reference:

{resources}

Thank you!
"""
                        }]
                    }]
                }
            elif step is None and not self.is_delete:
                message = {
                    "blocks": [{
                        "type": "context",
                        "elements": [{
                                "type": "mrkdwn",
                                "text": f"""*Unused Resource now being used [IN USE]*
Our telemetry has detected that following unused EC2 instance of User @{user.split('@')[0]} in AWS is now being used since it was restarted and will be taken out of PENDING DELETE status.

{resources}

Thank you!
"""
                        }]
                    }]
                }
            elif step is None and self.is_delete:
                message = {
                    "blocks": [{
                        "type": "context",
                        "elements": [{
                                "type": "mrkdwn",
                                "text": f"""*Unused Resource not found in AWS [DELETED]*
Our telemetry has detected your following unused EC2 instance of User @{user.split('@')[0]} in AWS was terminated. Hence, this concludes messages for this specific resource.

{resources}

Thank you!
"""
                        }]
                    }]
                }
        elif self.resource_type == 'IAMRoleEC2Instance':
            message = {
                "blocks": [{
                    "type": "context",
                    "elements": [{
                            "type": "mrkdwn",
                            "text": f"""*Over Permissive IAM Role Policies for EC2 Instance [DELETED]*
This is to inform you that following over permissive policies have been detached/deleted from IAM Role attached to EC2 Instance created by @{user.split('@')[0]}:

{resources}

Thank you!
"""
                    }]
                }]
            }
        elif self.resource_type == 'SecurityGroups':
            message = {
                "blocks": [{
                    "type": "context",
                    "elements": [{
                            "type": "mrkdwn",
                            "text": f"""*{"Unused Launch Wizard Security Groups Found in AWS [DELETED]" if is_launch_wizard else "Unused Security Groups Found in AWS [DELETED]"}*
This is to inform you that following unused Security Groups of User @{user.split('@')[0]} in AWS have been deleted:

{resources}

Thank you!
"""
                    }]
                }]
            }
        elif self.resource_type == 'EBSVolumes':
            message = {
                "blocks": [{
                    "type": "context",
                    "elements": [{
                            "type": "mrkdwn",
                            "text": f"""*Unused EBS Volumes Found in AWS*
Our telemetry has indicated that @{user.split('@')[0]} has unused resources in Amazon Web Services. Following are the EBS Volumes in 'available' state with details including the AWS account, Region & timestamp:

{resources}

Thank you!
"""
                    }]
                }]
            }
        try:
            if message:
                for url in self.webhooks:
                    if url.startswith("xoxb"):
                        oauth_token, channel_id = url.split(":")
                        message["channel"] = channel_id
                        message_headers = { 'Content-Type': 'application/json; charset=UTF-8', "Authorization": f"Bearer {oauth_token}"}
                        response = requests.post("https://slack.com/api/chat.postMessage", headers=message_headers, json=message, timeout=30)
                        print(response.json())
                        if not response.json().get("ok"):
                            print("Failed to send block message:", response.json().get("error"))
                    else:
                        message_headers = {'Content-Type': 'application/json; charset=UTF-8'}
                        response = http_obj.request(uri=url, method='POST', headers=message_headers, body=json.dumps(message))
                        print(response)
            else:
                raise CustomException("Message was not generated")
        except CustomException as error:
            return False, f"{str(error)}"
        except Exception as error:
            return False, f"Could not send alert: {str(error)}"
        return True, "Alert sent successfully"

    def __send_msteams_message(self, user: str, resources: list, notified_at: str, current_date: str, is_launch_wizard: bool, step)  -> bool:
        message_headers = {'Content-Type': 'application/json; charset=UTF-8'}
        http_obj = Http()
        hour_diff = 0
        message = {}

        formatted_resources = []
        for item in resources:
            if ":" in item:
                parts = item.split(':**')
                title = parts[0].replace('*', '').strip()
                value = parts[1].replace('<br>', '').strip() if len(parts) > 1 else ''
                formatted_resources.append({"title": title, "value": value})
        if self.resource_type == 'EC2Instance':
            if notified_at is not None:
                timezone_abbrev = utils.extract_timezone_abbreviation(notified_at)
                difference = datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.strptime(notified_at, f'%b %d, %Y %I:%M %p {timezone_abbrev}').replace(tzinfo=pytz.timezone('CST6CDT')).astimezone(pytz.utc)
                hour_diff = int(difference.total_seconds() / 3600)

            if step == 1 and not hour_diff:
                message = {
                    "type": "message",
                    "attachments": [
                        {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": {
                            "type": "AdaptiveCard",
                            "body": [{
                                "type": "TextBlock",
                                "wrap": True,
                                "style": "heading",
                                "weight": "bolder",
                                "size": "medium",
                                "isSubtle": True,
                                "text": "Unused Resources Found in AWS [Initial Message]"
                            },{
                                "type": "TextBlock",
                                "wrap": True,
                                "separator": True,
                                "isSubtle": True,
                                "text": f"Our telemetry has indicated, <at>{user}</at> has unused resources in Amazon Web Services. These are EC2 instances in a 'stopped' state.\nHere are the resources created by **{user}**, including the AWS account, Region & timestamp:",
                            },{
                                "type": "FactSet",
                                "isSubtle": True,
                                "facts": formatted_resources
                            },{
                                "type": "TextBlock",
                                "wrap": True,
                                "separator": True,
                                "isSubtle": True,
                                "text": "If these AWS resources are no longer being used, we kindly ask that you backup your data as/if needed and terminate the resource(s). If the resource is needed, please 'start' the resource and utilize.\n\nThank you!",
                            }],
                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "version": "1.0",
                            "msteams": {
                                "width": "Full",
                                "entities": [
                                    {
                                        "type": "mention",
                                        "text": f"<at>{user}</at>",
                                        "mentioned": {
                                            "id": f"{user}",
                                            "name": f"{user}"
                                        }
                                    },
                                ]
                            }
                        }
                    }]
                }
            elif step == 2 and hour_diff >= 120:
                message = {
                    "type": "message",
                    "attachments": [
                        {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": {
                            "type": "AdaptiveCard",
                            "body": [{
                                "type": "TextBlock",
                                "wrap": True,
                                "style": "heading",
                                "weight": "bolder",
                                "size": "medium",
                                "isSubtle": True,
                                "text": "Unused Resources Found in AWS [Pending Deletion]"
                            },{
                                "type": "TextBlock",
                                "wrap": True,
                                "separator": True,
                                "isSubtle": True,
                                "text": f"On {notified_at}, we sent you an alert about unused resources of User <at>{user}</at> in AWS account. As of today {current_date}, the following resources that were sent in the previous alert have not been either 'terminated' or 'started' and are still in a 'stopped' state in Amazon Web Services:",
                            },{
                                "type": "FactSet",
                                "isSubtle": True,
                                "facts": formatted_resources
                            },{
                                "type": "TextBlock",
                                "wrap": True,
                                "separator": True,
                                "isSubtle": True,
                                "text": "Again, If you are no longer using these AWS resources, we kindly ask that you backup your data as/if needed and terminate the resource(s). If the resource is needed, please 'start' the resource and utilize.\nWe are now tagging the unused resources with a 'pending deletion' tag. In 14 days these resource(s) will be terminated entirely. Please take action now, otherwise these resources will be automatically terminated.\n\nThank you!",
                            }],
                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "version": "1.0",
                            "msteams": {
                                "width": "Full",
                                "entities": [
                                    {
                                        "type": "mention",
                                        "text": f"<at>{user}</at>",
                                        "mentioned": {
                                            "id": f"{user}",
                                            "name": f"{user}"
                                        }
                                    },
                                ]
                            }
                        }
                    }]
                }
            elif step == 3 and hour_diff >= 312:
                message = {
                    "type": "message",
                    "attachments": [
                        {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": {
                            "type": "AdaptiveCard",
                            "body": [{
                                "type": "TextBlock",
                                "wrap": True,
                                "style": "heading",
                                "weight": "bolder",
                                "size": "medium",
                                "isSubtle": True,
                                "text": "Unused Resources Found in AWS [Final Reminder]"
                            },{
                                "type": "TextBlock",
                                "wrap": True,
                                "separator": True,
                                "isSubtle": True,
                                "text": f"This is our 3rd attempt to message about unused resources of User <at>{user}</at> in AWS. In 24 hours these EC2 instances will be terminated:",
                            },{
                                "type": "FactSet",
                                "isSubtle": True,
                                "facts": formatted_resources
                            },{
                                "type": "TextBlock",
                                "wrap": True,
                                "separator": True,
                                "isSubtle": True,
                                "text": "Again, If these AWS resources are no longer being used, we kindly ask that you backup your data as/if needed and terminate the resource(s). If the resource is needed, please 'start' the resource and utilize.\n\nThank you!",
                            }],
                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "version": "1.0",
                            "msteams": {
                                "width": "Full",
                                "entities": [
                                    {
                                        "type": "mention",
                                        "text": f"<at>{user}</at>",
                                        "mentioned": {
                                            "id": f"{user}",
                                            "name": f"{user}"
                                        }
                                    },
                                ]
                            }
                        }
                    }]
                }
            elif step == 4 and hour_diff >= 24:
                message = {
                    "type": "message",
                    "attachments": [
                        {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": {
                            "type": "AdaptiveCard",
                            "body": [{
                                "type": "TextBlock",
                                "wrap": True,
                                "style": "heading",
                                "weight": "bolder",
                                "size": "medium",
                                "isSubtle": True,
                                "text": "Unused Resources Found in AWS [TERMINATED]"
                            },{
                                "type": "TextBlock",
                                "wrap": True,
                                "separator": True,
                                "isSubtle": True,
                                "text": f"This is to inform you that unused EC2 instances of User <at>{user}</at> in AWS have been terminated.\nPrior to termination, we created an Amazon Machine Image (AMI) of the instance and tagged it with **Owner = {user}**. Including the AMI ID below for your reference:",
                            },{
                                "type": "FactSet",
                                "isSubtle": True,
                                "facts": formatted_resources
                            }],
                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "version": "1.0",
                            "msteams": {
                                "width": "Full",
                                "entities": [
                                    {
                                        "type": "mention",
                                        "text": f"<at>{user}</at>",
                                        "mentioned": {
                                            "id": f"{user}",
                                            "name": f"{user}"
                                        }
                                    },
                                ]
                            }
                        }
                    }]
                }
            elif step is None and not self.is_delete:
                message = {
                    "type": "message",
                    "attachments": [
                        {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": {
                            "type": "AdaptiveCard",
                            "body": [{
                                "type": "TextBlock",
                                "wrap": True,
                                "style": "heading",
                                "weight": "bolder",
                                "size": "medium",
                                "isSubtle": True,
                                "text": "Unused Resource now being used [IN USE]"
                            },{
                                "type": "TextBlock",
                                "wrap": True,
                                "separator": True,
                                "isSubtle": True,
                                "text": f"Our telemetry has detected that following unused EC2 instance of User <at>{user}</at> in AWS is now being used since it was restarted and will be taken out of PENDING DELETE status:",
                            },{
                                "type": "FactSet",
                                "isSubtle": True,
                                "facts": formatted_resources
                            }],
                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "version": "1.0",
                            "msteams": {
                                "width": "Full",
                                "entities": [
                                    {
                                        "type": "mention",
                                        "text": f"<at>{user}</at>",
                                        "mentioned": {
                                            "id": f"{user}",
                                            "name": f"{user}"
                                        }
                                    },
                                ]
                            }
                        }
                    }]
                }
            elif step is None and self.is_delete:
                message = {
                    "type": "message",
                    "attachments": [
                        {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": {
                            "type": "AdaptiveCard",
                            "body": [{
                                "type": "TextBlock",
                                "wrap": True,
                                "style": "heading",
                                "weight": "bolder",
                                "size": "medium",
                                "isSubtle": True,
                                "text": "Unused Resource not found in AWS [DELETED]"
                            },{
                                "type": "TextBlock",
                                "wrap": True,
                                "separator": True,
                                "isSubtle": True,
                                "text": f"Our telemetry has detected your following unused EC2 instance of User <at>{user}</at> in AWS was terminated. Hence, this concludes messages for this specific resource:",
                            },{
                                "type": "FactSet",
                                "isSubtle": True,
                                "facts": formatted_resources
                            }],
                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "version": "1.0",
                            "msteams": {
                                "width": "Full",
                                "entities": [
                                    {
                                        "type": "mention",
                                        "text": f"<at>{user}</at>",
                                        "mentioned": {
                                            "id": f"{user}",
                                            "name": f"{user}"
                                        }
                                    },
                                ]
                            }
                        }
                    }]
                }
        elif self.resource_type == 'IAMRoleEC2Instance':
            message = {
                "type": "message",
                "attachments": [
                    {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "body": [{
                            "type": "TextBlock",
                            "wrap": True,
                            "style": "heading",
                            "weight": "bolder",
                            "size": "medium",
                            "isSubtle": True,
                            "text": "Over Permissive IAM Role Policies for EC2 Instance [DELETED]"
                        },{
                            "type": "TextBlock",
                            "wrap": True,
                            "separator": True,
                            "isSubtle": True,
                            "text": f"This is to inform you that the following over permissive policies have been detached/deleted from IAM Role attached to EC2 Instance created by <at>{user}</at>:",
                        },{
                            "type": "FactSet",
                            "isSubtle": True,
                            "facts": formatted_resources
                        }],
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "version": "1.0",
                        "msteams": {
                            "width": "Full",
                            "entities": [
                                {
                                    "type": "mention",
                                    "text": f"<at>{user}</at>",
                                    "mentioned": {
                                        "id": f"{user}",
                                        "name": f"{user}"
                                    }
                                },
                            ]
                        }
                    }
                }]
            }
        elif self.resource_type == 'SecurityGroups':
            message = {
                "type": "message",
                "attachments": [
                    {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "body": [{
                            "type": "TextBlock",
                            "wrap": True,
                            "style": "heading",
                            "weight": "bolder",
                            "size": "medium",
                            "isSubtle": True,
                            "text": "Unused Launch Wizard Security Groups Found in AWS [DELETED]" if is_launch_wizard else "Unused Security Groups Found in AWS [DELETED]"
                        },{
                            "type": "TextBlock",
                            "wrap": True,
                            "separator": True,
                            "isSubtle": True,
                            "text": f"This is to inform you that following unused Security Groups of User <at>{user}</at> in AWS have been deleted:""",
                        },{
                            "type": "FactSet",
                            "isSubtle": True,
                            "facts": formatted_resources
                        }],
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "version": "1.0",
                        "msteams": {
                            "width": "Full",
                            "entities": [
                                {
                                    "type": "mention",
                                    "text": f"<at>{user}</at>",
                                    "mentioned": {
                                        "id": f"{user}",
                                        "name": f"{user}"
                                    }
                                },
                            ]
                        }
                    }
                }]
            }
        elif self.resource_type == 'EBSVolumes':
            message = {
                "type": "message",
                "attachments": [
                    {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "body": [{
                            "type": "TextBlock",
                            "wrap": True,
                            "style": "heading",
                            "weight": "bolder",
                            "size": "medium",
                            "isSubtle": True,
                            "text": "Unused EBS Volumes Found in AWS"
                        },{
                            "type": "TextBlock",
                            "wrap": True,
                            "separator": True,
                            "isSubtle": True,
                            "text": f"Our telemetry has indicated that <at>{user}</at> has unused resources in Amazon Web Services. Following are the EBS Volumes in 'available' state with details including the AWS account, Region & timestamp:",
                        },{
                            "type": "FactSet",
                            "isSubtle": True,
                            "facts": formatted_resources
                        }],
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "version": "1.0",
                        "msteams": {
                            "width": "Full",
                            "entities": [
                                {
                                    "type": "mention",
                                    "text": f"<at>{user}</at>",
                                    "mentioned": {
                                        "id": f"{user}",
                                        "name": f"{user}"
                                    }
                                },
                            ]
                        }
                    }
                }]
            }
        try:
            if message:
                for url in self.webhooks:
                    http_obj.request(uri=url, method='POST', headers=message_headers, body=json.dumps(message))
            else:
                raise CustomException("Message was not generated")
        except CustomException as error:
            return False, f"{str(error)}"
        except Exception as error:
            return False, f"Could not send alert: {str(error)}"
        return True, "Alert sent successfully"

    def __send_googlechat_message(self, user: str, resources: list, notified_at: str, current_date: str, is_launch_wizard: bool, step)  -> bool:
        message_headers = {'Content-Type': 'application/json; charset=UTF-8'}
        http_obj = Http()
        hour_diff = 0
        message = {}

        resources = "<br>".join([str(elem) for elem in resources])

        if self.resource_type == 'EC2Instance':
            if notified_at is not None:
                timezone_abbrev = utils.extract_timezone_abbreviation(notified_at)
                difference = datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.strptime(notified_at, f'%b %d, %Y %I:%M %p {timezone_abbrev}').replace(tzinfo=pytz.timezone('CST6CDT')).astimezone(pytz.utc)
                hour_diff = int(difference.total_seconds() / 3600)

            if step == 1 and not hour_diff:
                message = {
                    "cards": [{
                        "sections": [{
                            "widgets": [{
                                "textParagraph": {
                                    "text": f"""<b>Unused Resources Found in AWS [Initial Message]</b>

                                    Our telemetry has indicated, <b>{user}</b> has unused resources in Amazon Web Services. These are EC2 instances in a 'stopped' state.
                                    Here are the resources created by <b>{user}</b>, including the AWS account, Region & timestamp:

                                    {resources}

                                    If these AWS resources are no longer being used, we kindly ask that you backup your data as/if needed and terminate the resource(s). If the resource is needed, please 'start' the resource and utilize.

                                    Thank you!
                                    """
                                }
                            }]
                        }]
                    }]
                }
            elif step == 2 and hour_diff >= 120:
                message = {
                    "cards": [{
                        "sections": [{
                            "widgets": [{
                                "textParagraph": {
                                    "text": f"""<b>Unused Resources Found in AWS [Pending Deletion]</b>

                                    On {notified_at}, we sent you an email about unused resources of User {user} in your account. As of today {current_date}, the following resources that were sent in the previous message have not been either 'terminated' or 'started' and are still in a 'stopped' state in Amazon Web Services:

                                    {resources}

                                    Again, If these AWS resources are no longer being used, we kindly ask that you backup your data as/if needed and terminate the resource(s). If the resource is needed, please 'start' the resource and utilize.
                                    We are now tagging the unused resources with a 'Pending Deletion' tag. In 14 days these resource(s) will be terminated entirely. Please take action now, otherwise these resources will be automatically terminated.

                                    Thank you!
                                    """
                                }
                            }]
                        }]
                    }]
                }
            elif step == 3 and hour_diff >= 312:
                message = {
                    "cards": [{
                        "sections": [{
                            "widgets": [{
                                "textParagraph": {
                                    "text": f"""<b>Unused Resources Found in AWS [Final Reminder]</b>

                                    This is our 3rd attempt to message about unused resources of User {user} in AWS. In 24 hours these EC2 instances will be terminated:

                                    {resources}

                                    Again, If these AWS resources are no longer being used, we kindly ask that you backup your data as/if needed and terminate the resource(s). If the resource is needed, please 'start' the resource and utilize.

                                    Thank you!
                                    """
                                }
                            }]
                        }]
                    }]
                }
            elif step == 4 and hour_diff >= 24:
                message = {
                    "cards": [{
                        "sections": [{
                            "widgets": [{
                                "textParagraph": {
                                    "text": f"""<b>Unused Resources Found in AWS [TERMINATED]</b>

                                    This is to inform you that unused EC2 instances of User {user} in AWS have been terminated.
                                    Prior to termination, we created an Amazon Machine Image (AMI) of the instance and tagged it with <b>Owner = {user}</b>. Including the AMI ID below for your reference:

                                    {resources}

                                    Thank you!
                                    """
                                }
                            }]
                        }]
                    }]
                }
            elif step is None and not self.is_delete:
                message = {
                    "cards": [{
                        "sections": [{
                            "widgets": [{
                                "textParagraph": {
                                    "text": f"""<b>Unused Resource now being used [IN USE]</b>

                                    Our telemetry has detected that following unused EC2 instance of User {user} in AWS is now being used since it was restarted and will be taken out of PENDING DELETE status.

                                    {resources}

                                    Thank you!
                                    """
                                }
                            }]
                        }]
                    }]
                }
            elif step is None and self.is_delete:
                message = {
                    "cards": [{
                        "sections": [{
                            "widgets": [{
                                "textParagraph": {
                                    "text": f"""<b>Unused Resource not found in AWS [DELETED]</b>

                                    Our telemetry has detected your following unused EC2 instance of User {user} in AWS was terminated. Hence, this concludes messages for this specific resource.

                                    {resources}

                                    Thank you!
                                    """
                                }
                            }]
                        }]
                    }]
                }
        elif self.resource_type == 'IAMRoleEC2Instance':
            message = {
                "cards": [{
                    "sections": [{
                        "widgets": [{
                            "textParagraph": {
                                "text": f"""<b>Over Permissive IAM Role Policies for EC2 Instance [DELETED]</b>

                                This is to inform you that the following over permissive policies have been detached/deleted from IAM Role attached to EC2 Instance created by {user}:

                                {resources}

                                Thank you!
                                """
                            }
                        }]
                    }]
                }]
            }
        elif self.resource_type == 'SecurityGroups':
            message = {
                "cards": [{
                    "sections": [{
                        "widgets": [{
                            "textParagraph": {
                                "text": f"""<b>{"Unused Launch Wizard Security Groups Found in AWS [DELETED]" if is_launch_wizard else "Unused Security Groups Found in AWS [DELETED]"}</b>

                                This is to inform you that following unused Security Groups of User {user} in AWS have been deleted:

                                {resources}

                                Thank you!
                                """
                            }
                        }]
                    }]
                }]
            }
        elif self.resource_type == 'EBSVolumes':
            message = {
                "cards": [{
                    "sections": [{
                        "widgets": [{
                            "textParagraph": {
                                "text": f"""<b>Unused EBS Volumes Found in AWS</b>

                                Our telemetry has indicated that <b>{user}</b> has unused resources in Amazon Web Services. Following are the EBS Volumes in 'available' state with details including the AWS account, Region & timestamp:

                                {resources}

                                Thank you!
                                """
                            }
                        }]
                    }]
                }]
            }
        try:
            if message:
                for url in self.webhooks:
                    http_obj.request(uri=url, method='POST', headers=message_headers, body=json.dumps(message))
            else:
                raise CustomException("Message was not generated")
        except CustomException as error:
            return False, f"{str(error)}"
        except Exception as error:
            return False, f"Could not send alert: {str(error)}"
        return True, "Alert sent successfully"

    def send_email(self, sender_email: str, user: str, resources: list, notified_at: str, current_date: str, is_launch_wizard: bool, step) -> bool:
        msg = MIMEMultipart('mixed')
        msg['From'] = sender_email
        msg['To'] = user
        msg_body = MIMEMultipart('alternative')
        hour_diff = 0

        if self.resource_type == 'EC2Instance':
            if notified_at is not None:
                timezone_abbrev = utils.extract_timezone_abbreviation(notified_at)
                difference = datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.strptime(notified_at, f'%b %d, %Y %I:%M %p {timezone_abbrev}').replace(tzinfo=pytz.timezone('CST6CDT')).astimezone(pytz.utc)
                hour_diff = int(difference.total_seconds() / 3600)

            email_subject = ''
            body_html = ''

            if step == 1 and not hour_diff:
                email_subject = "Unused Resources Found in AWS [Initial Message]"
                body_html = f"""
                <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
                    <p>Hello {user},</p>
                    Our telemetry has indicated you have unused resources in Amazon Web Services. These are EC2 instances in a 'stopped' state.<br>
                    Here are the resources created by you, including the AWS account, Region & timestamp:<br><br>
                    <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                        {"<br>".join([str(elem) for elem in resources])}
                    </div><br>
                    If you are no longer using these AWS resources, we kindly ask that you backup your data as/if needed and terminate the resource(s). If the resource is needed, please 'start' the resource and utilize.<br><br>
                    Thank you!
                </body>
                """
            elif step == 2 and hour_diff >= 120:
                email_subject = "Unused Resources Found in AWS [Pending Deletion]"
                body_html = f"""
                <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
                    <p>Hello {user},</p>
                    On {notified_at}, we sent you an email about unused resources in your account. As of today {current_date}, the following resources that were sent in the previous message have not been either 'terminated' or 'started' and are still in a 'stopped' state in Amazon Web Services.<br><br>
                    Here are the remaining resources:<br><br>
                    <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                        {"<br>".join([str(elem) for elem in resources])}
                    </div><br>
                    Again, If you are no longer using these AWS resources, we kindly ask that you backup your data as/if needed and terminate the resource(s). If the resource is needed, please 'start' the resource and utilize.<br><br>
                    We are now tagging the unused resources with a 'pending deletion' tag. In 14 days these resource(s) will be terminated entirely. Please take action now, otherwise these resources will be automatically terminated.<br><br>
                    Thank you!
                </body>
                """
            elif step == 3 and hour_diff >= 312:
                email_subject = "Unused Resources Found in AWS [Final Reminder]"
                body_html = f"""
                <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
                    <p>Hello {user},</p>
                    This is our 3rd attempt to message you about unused resources in AWS. In 24 hours these EC2 instances will be terminated:<br><br>
                    <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                        {"<br>".join([str(elem) for elem in resources])}
                    </div><br>
                    Again, If you are no longer using these AWS resources, we kindly ask that you backup your data as/if needed and terminate the resource(s). If the resource is needed, please 'start' the resource and utilize.<br><br>
                    Thank you!
                </body>
                """
            elif step == 4 and hour_diff >= 24:
                email_subject = "Unused Resources Found in AWS [TERMINATED]"
                body_html = f"""
                <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
                    <p>Hello {user},</p>
                    This is to inform you that your unused EC2 instances in AWS have been terminated.<br>
                    Prior to termination, we created an Amazon Machine Image (AMI) of the instance and tagged it with <b>Owner = {user}</b>. Including the AMI ID below for your reference:<br><br>
                    <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                        {"<br>".join([str(elem) for elem in resources])}
                    </div><br>
                    Thank you!
                </body>
                """
            elif step is None and not self.is_delete:
                email_subject = "Unused Resource now being used [IN USE]"
                body_html = f"""
                <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
                    <p>Hello {user},</p>
                    Our telemetry has detected that your following unused EC2 instance in AWS is now being used since it was restarted and will be taken out of PENDING DELETE status.<br>
                    <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                        {"<br>".join([str(elem) for elem in resources])}
                    </div><br>
                    Thank you!
                </body>
                """
            elif step is None and self.is_delete:
                email_subject = "Unused Resource not found in AWS [DELETED]"
                body_html = f"""
                <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
                    <p>Hello {user},</p>
                    Our telemetry has detected your following unused EC2 instance in AWS was terminated. Hence, this concludes messages for this specific resource.<br>
                    <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                        {"<br>".join([str(elem) for elem in resources])}
                    </div><br>
                    Thank you!
                </body>
                """
        elif self.resource_type == 'IAMRoleEC2Instance':
            email_subject = "Over Permissive IAM Role Policies for EC2 Instance [DELETED]"
            body_html = f"""
            <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
                <p>Hello {user},</p>
                This is to inform you that the following over permissive policies have been detached/deleted from IAM Role attached to EC2 Instance:<br><br>
                <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                    {"<br>".join([str(elem) for elem in resources])}
                </div><br>
                Thank you!
            </body>
            """
        elif self.resource_type == 'SecurityGroups':
            email_subject = "Unused Launch Wizard Security Groups Found in AWS [DELETED]" if is_launch_wizard else "Unused Security Groups Found in AWS [DELETED]"
            body_html = f"""
            <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
                <p>Hello {user},</p>
                This is to inform you that your unused Security Groups in AWS have been deleted. Following are the details for those:<br><br>
                <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                    {"<br>".join([str(elem) for elem in resources])}
                </div><br>
                Thank you!
            </body>
            """
        elif self.resource_type == 'EBSVolumes':
            email_subject = "Unused EBS Volumes Found in AWS"
            body_html = f"""
            <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
                <p>Hello {user},</p>
                Our telemetry has indicated you have unused resources in Amazon Web Services. These are EBS Volumes in 'available' state.<br>
                Here are the volumes created by you, including the AWS account, Region & timestamp:<br><br>
                <div style="background-color:#ffffff; margin-right: 150px;padding:5px 20px 5px 20px;border-radius: 10px">
                    {"<br>".join([str(elem) for elem in resources])}
                </div><br><br>
                Thank you!
            </body>
            """
        try:
            ses = boto3.client('ses')
            if body_html:
                msg['Subject'] = email_subject
                htmlpart = MIMEText(body_html.encode("utf-8"), 'html', "utf-8")
                msg_body.attach(htmlpart)
                msg.attach(msg_body)

                ses.send_raw_email(
                    Source=sender_email,
                    Destinations=[user],
                    RawMessage={'Data':msg.as_string()}
                )
            else:
                raise CustomException("Email Message was not generated.")
        except CustomException as error:
            return False, f"{str(error)}"
        except Exception as error:
            return False, f"Could not send email to {user}: {str(error)}"
        return True, "Email message sent successfully"
