def daily_alert(notification_app, date, sg_resources_data, iam_resources_data, s3_resources_data, root_logins_resources_data, remediated_resources_data):
    """
    Returns Message in json format which will be sent as an app notification using Webhook URL
    Args:
        notification_app
        date
        sg_resources_data
        iam_resources_data
        s3_resources_data
        root_logins_resources_data
        remediated_resources_data
    Returns:
        message (based on app chosen)
    """
    sg_card_section = {}
    iam_card_section = {}
    s3_card_section = {}
    root_logins_card_section = {}
    remediated_resources_card_section = {}
    if len(sg_resources_data) != 0:
        if notification_app == 'googlechat':
            sg_card_section = {
                "header": "<font color=\"#FF0000\">Security Groups With Open Ports</font>",
                "widgets": [sg_resources_data]
            }
        elif notification_app == 'slack':
            sg_card_section = [{
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": "*`Security Groups With Open Ports`*"
                }]
            }]
            sg_card_section.extend(sg_resources_data)
        elif notification_app == 'msteams':
            sg_card_section = []
            headers_sg = ['Security Group ID', 'Account ID', 'Region', 'Attached', 'Open To', 'Ports', 'Notifications Suppressed']
            sg_card_section.append('<p style="font-size: 14px; color:red;"><b>Security Groups with Open Ports</b></p>')
            sg_card_section.append('<table border="1">')
            sg_card_section.append('<tr>')
            for label in headers_sg:
                sg_card_section.append(f'<th style="padding:5px">{label}</th>')
            sg_card_section.append('</tr>')
            sg_card_section = ''.join([str(elem) for elem in sg_card_section])
            sg_resources_data = ''.join([str(elem) for elem in sg_resources_data])
            sg_card_section = sg_card_section+sg_resources_data+'</table><br>'
    if len(iam_resources_data) != 0:
        if notification_app == 'googlechat':
            iam_card_section = {
                "header": "<font color=\"#FF0000\">IAM Users</font>",
                "widgets": [iam_resources_data]
            }
        elif notification_app == 'slack':
            iam_card_section = [{
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": "*`IAM Users`*"
                }]
            }]
            iam_card_section.extend(iam_resources_data)
        elif notification_app == 'msteams':
            iam_card_section = []
            headers_iam = ['IAM User', 'Account ID', 'Programmatic Access', 'Console Access', 'Notifications Suppressed']
            iam_card_section.append('<p style="font-size: 14px; color:red;"><b>IAM Users</b></p>')
            iam_card_section.append('<table border="1">')
            iam_card_section.append('<tr>')
            for label in headers_iam:
                iam_card_section.append(f'<th style="padding:5px">{label}</th>')
            iam_card_section.append('</tr>')
            iam_card_section = ''.join([str(elem) for elem in iam_card_section])
            iam_resources_data = ''.join([str(elem) for elem in iam_resources_data])
            iam_card_section = iam_card_section+iam_resources_data+'</table><br>'
    if len(s3_resources_data) != 0:
        if notification_app == 'googlechat':
            s3_card_section = {
                "header": "<font color=\"#FF0000\">Public S3 Buckets</font>",
                "widgets": [s3_resources_data]
            }
        elif notification_app == 'slack':
            s3_card_section = [{
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": "*`Public S3 Buckets`*"
                }]
            }]
            s3_card_section.extend(s3_resources_data)
        elif notification_app == 'msteams':
            s3_card_section = []
            headers_s3 = ['S3 Bucket Name', 'Account ID', 'Region', 'Encrypted', 'Public Bucket', 'Public Objects', 'Notifications Suppressed']
            s3_card_section.append('<p style="font-size: 14px; color:red;"><b>Public S3 Buckets</b></p>')
            s3_card_section.append('<table border="1">')
            s3_card_section.append('<tr>')
            for label in headers_s3:
                s3_card_section.append(f'<th style="padding:5px">{label}</th>')
            s3_card_section.append('</tr>')
            s3_card_section = ''.join([str(elem) for elem in s3_card_section])
            s3_resources_data = ''.join([str(elem) for elem in s3_resources_data])
            s3_card_section = s3_card_section+s3_resources_data+'</table><br>'
    if len(root_logins_resources_data) != 0:
        if notification_app == 'googlechat':
            root_logins_card_section = {
                "widgets": [root_logins_resources_data]
            }
    if len(remediated_resources_data) != 0:
        if notification_app == 'googlechat':
            remediated_resources_card_section = {
                "widgets": [remediated_resources_data]
            }
    message = {}
    if notification_app == 'googlechat':
        if len(sg_resources_data) != 0 or len(iam_resources_data) != 0 or len(s3_resources_data) != 0 or len(remediated_resources_data) != 0 or len(root_logins_resources_data) != 0:
            nonremediated_card = {}
            remediated_card = {}
            root_user_logins_card = {}
            if len(sg_resources_data) != 0 or len(iam_resources_data) != 0 or len(s3_resources_data) != 0:
                nonremediated_card = {
                    "cardId": "nonremediated-daily-alerts",
                    "card": {
                        "header": {
                            "title": "Outstanding Issues (not yet remediated)",
                        },
                        "sections": [
                            sg_card_section,
                            iam_card_section,
                            s3_card_section
                        ]
                    }
                }
            if len(root_logins_resources_data) != 0:
                root_user_logins_card = {
                    "cardId": "root-user-logins-daily-alerts",
                    "card": {
                        "header": {
                            "title": "Root User Logins (in last 24hrs)",
                        },
                        "sections": [root_logins_card_section]
                    }
                }
            if len(remediated_resources_data) != 0:
                remediated_card = {
                    "cardId": "remediated-daily-alerts",
                    "card": {
                        "header": {
                            "title": "Remediated Resources (in last 24hrs)",
                        },
                        "sections": [remediated_resources_card_section]
                    }
                }
            message = {
                "cardsV2": [{
                    "cardId": "daily-alerts",
                    "card": {
                        "header": {
                            "title": f"AWS Security Summary for {date}",
                        }
                    }
                },
                nonremediated_card,
                root_user_logins_card,
                remediated_card
            ]
            }
    elif notification_app == 'slack':
        if len(sg_resources_data) != 0 or len(iam_resources_data) != 0 or len(s3_resources_data) != 0 or len(remediated_resources_data) != 0 or len(root_logins_resources_data) != 0:
            nonremediated_block = {}
            remediated_block = {}
            root_user_logins_block = {}
            if len(sg_resources_data) != 0 or len(iam_resources_data) != 0 or len(s3_resources_data) != 0:
                nonremediated_block = [{
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": ":heavy_exclamation_mark: *Outstanding Issues (not yet remediated)*"
                    }
                }]
                nonremediated_block.extend(sg_card_section)
                nonremediated_block.extend(iam_card_section)
                nonremediated_block.extend(s3_card_section)
            if len(remediated_resources_data) != 0:
                remediated_block = [{
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": ":white_check_mark: *Remediated Resources (in last 24hrs)*"
                    }
                }]
                remediated_block.extend(remediated_resources_data)
            if len(root_logins_resources_data) != 0:
                root_user_logins_block = [{
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": ":heavy_exclamation_mark: *Root User Logins (in last 24hrs)*"
                    }
                }]
                root_user_logins_block.extend(root_logins_resources_data)
            message = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"AWS Security Summary for {date}",
                            "emoji": True
                        }
                    },
                    {
                        "type": "divider"
                    }
                ]
            }
            message['blocks'].extend(nonremediated_block)
            message['blocks'].extend(root_user_logins_block)
            message['blocks'].extend(remediated_block)
    elif notification_app == 'msteams':
        if len(sg_resources_data) != 0 or len(iam_resources_data) != 0 or len(s3_resources_data) != 0 or len(remediated_resources_data) != 0 or len(root_logins_resources_data) != 0:
            nonremediated_block = {}
            remediated_block = {}
            root_user_logins_block = {}
            if len(sg_resources_data) != 0 or len(iam_resources_data) != 0 or len(s3_resources_data) != 0:
                sg_card_section = ''.join([str(elem) for elem in sg_card_section])
                iam_card_section = ''.join([str(elem) for elem in iam_card_section])
                s3_card_section = ''.join([str(elem) for elem in s3_card_section])
                nonremediated_block = [{
                    "activityTitle": "<p style='font-size: 16px;'><b> &#x2757; Outstanding Issues (not yet remediated)</b></p>",
                    "markdown": True
                },{
                    "text": sg_card_section+iam_card_section+s3_card_section
                }]
            if len(root_logins_resources_data) != 0:
                table_header_block = []
                headers_root_logins = ['Account ID', 'Time of Login']
                table_header_block.append('<table border="1">')
                table_header_block.append('<tr>')
                for label in headers_root_logins:
                    table_header_block.append(f'<th style="padding:5px">{label}</th>')
                table_header_block.append('</tr>')
                table_header_block = ''.join([str(elem) for elem in table_header_block])
                root_logins_resources_data = ''.join([str(elem) for elem in root_logins_resources_data])
                root_logins_resources_data = table_header_block+root_logins_resources_data+'</table>'
                root_user_logins_block = [{
                    "activityTitle": "<p style='font-size: 16px;'><b> &#x2757; Root User Logins (in last 24hrs)</b></p>",
                    "markdown": True
                },{
                    "text": root_logins_resources_data
                }]
            if len(remediated_resources_data) != 0:
                table_header_block = []
                table_header_block.append('<table border="1">')
                table_header_block.append('<tr>')
                header = ['Resource Type', 'Resource ID', 'Account ID', 'Region', 'Remediated At']
                for label in header:
                    table_header_block.append(f'<th style="padding:5px">{label}</th>')
                table_header_block.append('</tr>')
                table_header_block = ''.join([str(elem) for elem in table_header_block])
                remediated_resources_data = ''.join([str(elem) for elem in remediated_resources_data])
                remediated_resources_data = table_header_block+remediated_resources_data+'</table>'
                remediated_block = [{
                    "activityTitle": "<p style='font-size: 16px;'><b> &#x2705; Remediated Resources (in last 24hrs)</b></p>",
                    "markdown": True
                },{
                    "text": remediated_resources_data
                }]
            message = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": "Alert for daily AWS Security Summary",
                "themeColor": "0072C6",
                "title": f"AWS Security Summary for {date}"
            }
            message['sections'] = []
            message['sections'].extend(nonremediated_block)
            message['sections'].extend(root_user_logins_block)
            message['sections'].extend(remediated_block)
    return message
