import logging
import datetime
import time
import json
from os import getenv

MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
CLOUDTRAIL_THROTTLE_PERIOD = 0.5
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class CloudTrail:
    def __init__(self, active_session, region):
        self.region = region
        self.client = active_session.client(service_name='cloudtrail', region_name=self.region)

    def get_resource_details(self, event_name, resource_id):
        event_by = ''
        created_at = ''
        user = ''
        retry_attempts = 0
        delay = DELAY_SECONDS
        next_token = ''
        base_kwargs = {
            'LookupAttributes': [{
                'AttributeKey': 'ResourceName',
                'AttributeValue': resource_id
            }]
        }
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                cloudtrail_event = {}
                while next_token is not None:
                    kwargs = base_kwargs.copy()
                    if next_token != '':
                        kwargs.update({'NextToken': next_token})
                    response = self.client.lookup_events(**kwargs)
                    for event in response['Events']:
                        if event['EventName'] == event_name:
                            if 'Username' in event and 'EventTime' in event:
                                event_by = event['Username']
                                created_at = event['EventTime'].strftime("%Y-%m-%dT%H:%M:%S") if isinstance(event['EventTime'], datetime.datetime) else event['EventTime']
                            if 'CloudTrailEvent' in event:
                                cloudtrail_event = json.loads(event['CloudTrailEvent'])
                            break
                    time.sleep(CLOUDTRAIL_THROTTLE_PERIOD)
                    next_token = response['NextToken'] if 'NextToken' in response else None
                if '@' in event_by:
                    user = event_by
                elif 'userAgent' in cloudtrail_event:
                    user_agent = cloudtrail_event['userAgent']
                    if 'terraform.io' in user_agent:
                        user = "Terraform"
                    elif 'AWS Internal' in user_agent:
                        user = "AWS"
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return user, created_at
