import logging
from os import getenv

LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class CostOptimizer:
    def __init__(self, active_session, region):
        self.region = region
        self.client = active_session.client(service_name='compute-optimizer', region_name=self.region)

    def get_compute_optimizer_recommendations(self, instance_id, account_id):
        finding = "no status yet"
        try:
            response = self.client.get_ec2_instance_recommendations(
                instanceArns=[f'arn:aws:ec2:{self.region}:{account_id}:instance/{instance_id}']
            )
            if response['instanceRecommendations']:
                recommendation = response['instanceRecommendations'][0]
                finding = recommendation['finding']
        except self.client.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'OptInRequiredException':
                LOGGER.error("Compute Optimizer Not Enabled")
            LOGGER.error(str(error))
        return finding
