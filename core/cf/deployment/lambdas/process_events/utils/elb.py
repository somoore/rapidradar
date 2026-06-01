import logging
import time
from os import getenv

MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class ELB:
    def __init__(self, active_session, region):
        self.region = region
        self.elb_client = active_session.client(service_name='elb', region_name=self.region)
        self.elbv2_client = active_session.client(service_name='elbv2', region_name=self.region)

    def get_lb_details(self, loadbalancer_type, resource_id):
        vpc_id = None
        subnet_ids = []
        security_groups = []
        scheme = None
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                loadbalancer_details = {}
                if loadbalancer_type == 'Classic':
                    response = self.elb_client.describe_load_balancers(LoadBalancerNames=[resource_id])
                    if 'LoadBalancerDescriptions' in response and len(response['LoadBalancerDescriptions']) > 0:
                        loadbalancer_details = response['LoadBalancerDescriptions'][0]
                else:
                    response = self.elbv2_client.describe_load_balancers(LoadBalancerArns=[resource_id])
                    if 'LoadBalancers' in response and len(response['LoadBalancers']) > 0:
                        loadbalancer_details = response['LoadBalancers'][0]
                scheme = loadbalancer_details['Scheme']
                vpc_id = loadbalancer_details['VPCId'] if 'VPCId' in loadbalancer_details else loadbalancer_details['VpcId']
                subnet_ids = loadbalancer_details['Subnets'] if 'Subnets' in loadbalancer_details else [ az['SubnetId'] for az in loadbalancer_details['AvailabilityZones'] if 'AvailabilityZones' in loadbalancer_details ]
                if 'SecurityGroups' in loadbalancer_details:
                    security_groups = loadbalancer_details['SecurityGroups']
                break
            except self.elb_client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'AccessPointNotFoundException':
                    LOGGER.info("Loadbalancer %s not found", resource_id)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
            except self.elbv2_client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return vpc_id, subnet_ids, security_groups, scheme

    def update_attached_lb_security_groups(self, loadbalancer_type, resource_id, new_security_group_ids: list):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                if loadbalancer_type == 'Classic':
                    self.elb_client.apply_security_groups_to_load_balancer(
                        LoadBalancerName=resource_id,
                        SecurityGroups=new_security_group_ids
                    )
                    return True
                self.elbv2_client.set_security_groups(
                    LoadBalancerArn=resource_id,
                    SecurityGroups=new_security_group_ids
                )
                return True
            except self.elb_client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
            except self.elbv2_client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def tag_loadbalancer(self, loadbalancer_type, resource_id, tags):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                if loadbalancer_type == 'Classic':
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
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
            except self.elbv2_client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def __get_elb_loadbalancer_name(self, resource_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.elb_client.describe_load_balancers(PageSize=100)
                for lb in response['LoadBalancerDescriptions']:
                    if lb['LoadBalancerName'].startswith(resource_id):
                        return lb['LoadBalancerName']
                break
            except self.elb_client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return ''

    def __get_elbv2_loadbalancer_arn(self, resource_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.elbv2_client.describe_load_balancers(PageSize=100)
                for lb in response['LoadBalancers']:
                    if lb['LoadBalancerName'].startswith(resource_id):
                        return lb['LoadBalancerArn']
                break
            except self.elbv2_client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return ''

    def found_keep_alive_tag(self, resource_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = {}
                if resource_id.startswith('clb'):
                    loadbalancer_name = self.__get_elb_loadbalancer_name(resource_id[4:])
                    response = self.elb_client.describe_tags(LoadBalancerNames=[loadbalancer_name])
                else:
                    loadbalancer_arn = self.__get_elbv2_loadbalancer_arn(resource_id[4:])
                    response = self.elbv2_client.describe_tags(ResourceArns=[loadbalancer_arn])
                for tag_desc in response['TagDescriptions']:
                    for tag in tag_desc['Tags']:
                        if tag['Key'] == 'keep-alive' and tag['Value'] == 'true':
                            return True
                return False
            except self.elb_client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
            except self.elbv2_client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def delete_loadbalancer(self, resource_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                if resource_id.startswith('clb'):
                    loadbalancer_name = self.__get_elb_loadbalancer_name(resource_id[4:])
                    self.elb_client.delete_load_balancer(LoadBalancerName=loadbalancer_name)
                else:
                    loadbalancer_arn = self.__get_elbv2_loadbalancer_arn(resource_id[4:])
                    self.elbv2_client.delete_load_balancer(LoadBalancerArn=loadbalancer_arn)
                return True
            except self.elb_client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
            except self.elbv2_client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False
