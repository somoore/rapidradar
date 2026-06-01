from os import getenv
from pdpyras import APISession, EventsAPISession
from pagerduty.incidents import PagerDutyIncidents

AWS_ORG_NAME = getenv('AWS_ORG_NAME')

class PagerDuty:
    def __init__(self, account_id, account_name, region, is_pd_integration_type_restapi: bool, routing_key=None, api_token=None, service_id=None, from_user_email=None):
        self.account_id, self.account_name, self.region, self.is_pd_integration_type_restapi = account_id, account_name, region, is_pd_integration_type_restapi
        self.session = None
        self.service_id = None
        self.incident = PagerDutyIncidents(AWS_ORG_NAME, self.account_id, self.account_name, self.region)
        if self.is_pd_integration_type_restapi:
            self.session = APISession(api_token, from_user_email)
            self.service_id = service_id
            self.create_incident = self.__create_restapi_incident
            self.get_incident_details = self.__get_restapi_incident_details
            self.resolve_incident = self.__resolve_restapi_incident
        else:
            self.session = EventsAPISession(routing_key)
            self.create_incident = self.__create_eventsapi_incident
            self.resolve_incident = self.__resolve_eventsapi_incident

    @staticmethod
    def __get_urgency(severity) -> str:
        if severity in ['Critical']:
            return 'high'
        return 'low'

    @staticmethod
    def __get_severity(severity) -> str:
        if severity in ['CRITICAL']:
            return 'critical'
        if severity in ['HIGH', 'MEDIUM', 'LOW']:
            return 'warning'
        return 'info'

    def __create_restapi_incident(self, alert_id, incident_args: dict):
        title, details = self.incident.get_details(alert_id, incident_args)
        incident_payload = {
            "incident": {
                "type": "incident",
                "title": title,
                "service": {
                    "id": f"{self.service_id}",
                    "type": "service_reference"
                },
                "body": {
                    "type": "incident_body",
                    "details": details
                },
                "urgency": self.__get_urgency(incident_args['severity'])
            }
        }
        try:
            response = self.session.post('/incidents', json=incident_payload)
            if response.status_code // 100 == 2:
                incident_id = response.json()['incident']['id']
                incident_number = response.json()['incident']['incident_number']
                incident_url = response.json()['incident']['html_url']
                return incident_id, incident_number, incident_url
            print(f"Error creating PagerDuty incident: {response.status_code}, {response.text}")
            return None, None, None
        except Exception as error:
            raise error

    def __create_eventsapi_incident(self, alert_id, incident_args: dict):
        title, details = self.incident.get_details(alert_id, incident_args)
        incident_payload = {
            "routing_key": self.session.api_key,
            "event_action": "trigger",
            "payload": {
                "summary": title,
                "source": "AWS",
                "severity": self.__get_severity(incident_args['severity']),
                "custom_details": {
                    "account_id": f"{self.account_id}",
                    "account_name": f"{self.account_name}",
                    "region": f"{self.region}",
                    "details": details
                }
            }
        }
        try:
            response = self.session.post('/v2/enqueue', json=incident_payload)
            if response.status_code // 100 == 2:
                dedup_key = response.json()['dedup_key']
                return dedup_key
            print(f"Error creating PagerDuty incident: {response.status_code}, {response.text}")
            return None
        except Exception as error:
            raise error

    def __get_restapi_incident_details(self, incident_id):
        incident_status = ''
        try:
            response = self.session.get(f'/incidents/{incident_id}')
            if response.status_code // 100 == 2:
                incident_status = response.json()['incident']['status']
                incident_number = response.json()['incident']['incident_number']
                incident_url = response.json()['incident']['html_url']
                return incident_status, incident_number, incident_url
            print(f"Error getting details for PagerDuty incident {incident_id}: {response.status_code}, {response.text}")
            return None, None, None
        except Exception as error:
            raise error

    def __resolve_restapi_incident(self, incident_id):
        incident_payload = {
            "incident": {
                "type": "incident",
                "status": "resolved"
            }
        }
        try:
            response = self.session.put(f'/incidents/{incident_id}', json=incident_payload)
            if response.status_code // 100 == 2:
                return True
            print(f"Error resolving PagerDuty incident {incident_id}: {response.status_code}, {response.text}")
            return False
        except Exception as error:
            print(str(error))
            return False

    def __resolve_eventsapi_incident(self, dedup_key):
        try:
            self.session.resolve(dedup_key)
            return True
        except Exception as error:
            print(f"Error resolving PagerDuty incident: {str(error)}")
            return False
