import logging
import json
import time
from os import getenv

MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class Pricing:
    def __init__(self, active_session, region):
        self.region = region
        self.client = active_session.client(service_name='pricing', region_name='us-east-1')

    @staticmethod
    def __get_valid_rds_engine(engine: str):
        valid_engine = ''
        if engine == 'aurora-mysql':
            valid_engine = 'Aurora MySQL'
        elif engine == 'aurora-postgresql':
            valid_engine = 'Aurora PostgreSQL'
        elif engine == 'mariadb':
            valid_engine = 'MariaDB'
        elif engine == 'mysql':
            valid_engine = 'MySQL'
        elif engine == 'postgres':
            valid_engine = 'PostgreSQL'
        elif engine.startswith('sqlserver-'):
            valid_engine = 'SQL Server'
        elif engine.startswith('oracle-'):
            valid_engine = 'Oracle'
        return valid_engine

    def get_instance_cost(self, instance_type, cost_type, usage_operation, tenancy):
        hourly_cost, daily_cost, monthly_cost = '', '', ''
        if cost_type == 'on-demand':
            cost_type = ['On Demand']
        elif cost_type == 'scheduled':
            cost_type = ['Reservation', 'reserved']
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.get_products(
                    ServiceCode='AmazonEC2',
                    Filters=[
                        {'Type': 'TERM_MATCH', 'Field': 'instanceType', 'Value': instance_type},
                        {'Type': 'TERM_MATCH', 'Field': 'operation', 'Value': usage_operation},
                        {'Type': 'TERM_MATCH', 'Field': 'tenancy', 'Value': tenancy},
                        {'Type': 'TERM_MATCH', 'Field': 'regionCode', 'Value': self.region}
                    ],
                )
                price_per_unit = None
                for ls in response['PriceList']:
                    pr_list = json.loads(ls)
                    price_dimensions = pr_list['terms']['OnDemand'][list(pr_list['terms']['OnDemand'].keys())[0]]['priceDimensions']
                    description = price_dimensions[list(price_dimensions.keys())[0]]['description']
                    if any(value in description for value in cost_type):
                        price_per_unit = price_dimensions[list(price_dimensions.keys())[0]]['pricePerUnit'].get('USD')
                if price_per_unit is not None:
                    hourly_cost = float(price_per_unit)
                    daily_cost = hourly_cost * 24
                    monthly_cost = daily_cost * 30
                    hourly_cost = f"USD {hourly_cost:.2f}"
                    daily_cost = f"USD {daily_cost:.2f}"
                    monthly_cost = f"USD {monthly_cost:.2f}"
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return hourly_cost, daily_cost, monthly_cost

    def get_cluster_cost(self):
        hourly_cost, daily_cost, monthly_cost = '', '', ''
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.get_products(
                    ServiceCode='AmazonEKS',
                    Filters=[
                        {'Type': 'TERM_MATCH', 'Field': 'regionCode', 'Value': self.region}
                    ],
                )
                price_list = json.loads(response['PriceList'][0])
                price_per_unit = None
                for ls in response['PriceList']:
                    price_list = json.loads(ls)
                    if 'AmazonEKS-Hours:perCluster' in price_list['product']['attributes']['usagetype']:
                        for key, value in price_list['terms']['OnDemand'].items():
                            price_per_unit = value['priceDimensions'][list(value['priceDimensions'].keys())[0]]['pricePerUnit'].get('USD')
                            if price_per_unit:
                                break
                if price_per_unit is not None:
                    hourly_cost = float(price_per_unit)
                    daily_cost = hourly_cost * 24
                    monthly_cost = daily_cost * 30
                    hourly_cost = f"USD {hourly_cost:.2f}"
                    daily_cost = f"USD {daily_cost:.2f}"
                    monthly_cost = f"USD {monthly_cost:.2f}"
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return hourly_cost, daily_cost, monthly_cost

    def get_rds_hourly_cost(self, instance_class, engine, storage_type):
        hourly_cost = 0.0
        prod_filters = [
            {'Type': 'TERM_MATCH', 'Field': 'databaseEngine', 'Value': self.__get_valid_rds_engine(engine)},
            {'Type': 'TERM_MATCH', 'Field': 'termType', 'Value': 'OnDemand'},
            {'Type': 'TERM_MATCH', 'Field': 'regionCode', 'Value': self.region}
        ]
        if instance_class.startswith('db.serverless'):
            prod_filters.append({'Type': 'TERM_MATCH', 'Field': 'productFamily', 'Value': 'ServerlessV2' if instance_class == 'db.serverlessv2' else 'Serverless'})
        else:
            prod_filters.append({'Type': 'TERM_MATCH', 'Field': 'instanceType', 'Value': instance_class})
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.get_products(
                    ServiceCode='AmazonRDS',
                    Filters=prod_filters,
                )
                price_per_unit = None
                for ls in response['PriceList']:
                    pr_list = json.loads(ls)
                    price_dimensions = pr_list['terms']['OnDemand'][list(pr_list['terms']['OnDemand'].keys())[0]]['priceDimensions']
                    description = price_dimensions[list(price_dimensions.keys())[0]]['description']
                    if '-iop' in storage_type:
                        if 'IO-optimized' in description:
                            price_per_unit = price_dimensions[list(price_dimensions.keys())[0]]['pricePerUnit'].get('USD')
                            break
                    else:
                        price_per_unit = price_dimensions[list(price_dimensions.keys())[0]]['pricePerUnit'].get('USD')
                        break
                if price_per_unit is not None:
                    hourly_cost = float(price_per_unit)
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return hourly_cost

    def __get_efs_monthly_cost(self, storage_class):
        monthly_cost = ''
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.get_products(
                    ServiceCode='AmazonEFS',
                    Filters=[
                        {'Type': 'TERM_MATCH', 'Field': 'regionCode', 'Value': self.region},
                        {'Type': 'TERM_MATCH', 'Field': 'storageClass', 'Value': storage_class}
                    ]
                )
                price_per_unit = None
                for ls in response['PriceList']:
                    pr_list = json.loads(ls)
                    price_dimensions = pr_list['terms']['OnDemand'][list(pr_list['terms']['OnDemand'].keys())[0]]['priceDimensions']
                    price_dimension = price_dimensions[list(price_dimensions.keys())[0]]
                    if price_dimension['unit'] == 'GB-Mo':
                        price_per_unit = price_dimension['pricePerUnit'].get('USD')
                if price_per_unit is not None:
                    monthly_cost = float(price_per_unit)
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return monthly_cost

    def get_efs_cost(self, is_multi_az, standard_gb_hours, infa_gb_hours):
        general_purpose_storage_class = 'General Purpose'
        infa_storage_class = 'Infrequent Access'
        if not is_multi_az:
            general_purpose_storage_class = 'One Zone-' + general_purpose_storage_class
            infa_storage_class = 'One Zone-' + infa_storage_class

        general_purpose_cost = self.__get_efs_monthly_cost(general_purpose_storage_class)
        infa_cost = self.__get_efs_monthly_cost(infa_storage_class)
        general_purpose_monthly_cost = standard_gb_hours * (1 / 720) * general_purpose_cost
        infa_monthly_cost = infa_gb_hours * (1 / 720) * infa_cost

        monthly_cost = general_purpose_monthly_cost + infa_monthly_cost
        daily_cost = monthly_cost / 30
        hourly_cost = daily_cost / 24
        hourly_cost = f"USD {hourly_cost:.2f}"
        daily_cost = f"USD {daily_cost:.2f}"
        monthly_cost = f"USD {monthly_cost:.2f}"

        return hourly_cost, daily_cost, monthly_cost
