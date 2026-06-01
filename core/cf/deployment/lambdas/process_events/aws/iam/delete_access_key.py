from utils.dynamodb import DeleteData
from utils.events import Events
from utils.utility import AWSHelper
from utils.logger import LOGGER

def handle_event(helper: AWSHelper, event, project_name, iam_keypair_access_tracker_table):
    if 'errorCode' not in event and 'requestParameters' in event:
        events_utils = Events(helper.account_id, helper.region)
        request_params = event['requestParameters']
        active_session = helper.get_active_session()
        try:
            iam_user = request_params['userName']
            access_key_id = request_params['accessKeyId']

            if not events_utils.cleanup_rules_to_capture_iam_user_events(active_session, iam_user, access_key_id, project_name):
                LOGGER.error("Could not clean up EventBridge Rules for Access Key ID %s in Account %s", access_key_id, helper.account_id)
            if not DeleteData(iam_keypair_access_tracker_table).delete('iam_user', iam_user, 'access_key_id', access_key_id):
                LOGGER.error("Could not delete record for Access Key ID %s of IAM User %s of Account %s", access_key_id, iam_user, helper.account_id)
        except Exception as error:
            LOGGER.error(str(error))
