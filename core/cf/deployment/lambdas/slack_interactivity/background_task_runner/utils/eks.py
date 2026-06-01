from utils.logger import LOGGER

class EKS:
    def __init__(self, active_session, region):
        self.region = region
        self.client = active_session.client(service_name='eks', region_name=self.region)

    def add_tags_to_eks_cluster(self, account_id, resource: str, tags) -> bool:
        try:
            self.client.tag_resource(
                resourceArn=f'arn:aws:eks:{self.region}:{account_id}:cluster/{resource}',
                tags=tags
            )
            LOGGER.info("Successfully added following tags to EKS Cluster %s: %s", resource, tags)
            return True
        except self.client.exceptions.ClientError as error:
            LOGGER.error(str(error))
        return False
