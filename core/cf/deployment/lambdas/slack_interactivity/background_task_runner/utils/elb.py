from utils.logger import LOGGER

class ELB:
    def __init__(self, active_session, region):
        self.region = region
        self.elb_client = active_session.client(service_name='elb', region_name=self.region)
        self.elbv2_client = active_session.client(service_name='elbv2', region_name=self.region)

    def tag_loadbalancer(self, resource_type, resource_id, tags):
        try:
            if resource_type.startswith('Classic'):
                self.elb_client.add_tags(
                    LoadBalancerNames=[resource_id],
                    Tags=tags
                )
                return True
            self.elbv2_client.add_tags(
                ResourceArns=[resource_id],
                Tags=tags
            )
            return True
        except self.elb_client.exceptions.ClientError as error:
            LOGGER.error(str(error))
        except self.elbv2_client.exceptions.ClientError as error:
            LOGGER.error(str(error))
        return False
