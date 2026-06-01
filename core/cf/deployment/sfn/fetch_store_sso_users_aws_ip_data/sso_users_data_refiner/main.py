def lambda_handler(event, context):
    datetime_list = []
    refined_payload = []
    payload = {}
    latest_datetime = ''

    for payload in event:
        for item in payload:
            if item['LastActivity']:
                datetime_list.append(item['LastActivity'])
            refined_payload.append(item)
    if datetime_list:
        latest_datetime = max(datetime_list)
    for item in refined_payload:
        if item['LastActivity'] == latest_datetime:
            return item
    return {}
