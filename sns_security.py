import boto3
import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

region = os.environ.get('region')
account_id = os.environ.get('accountid')

# Ensure the environment variable 'Var_sns_list' is set
sns_list = os.environ.get('Var_sns_list')
if sns_list:
    sns_topics = sns_list.split(',')
else:
    sns_topics = []
    logger.warning("Environment variable 'Var_sns_list' is not set. No SNS topics to check.")

def check_sns_subscribers():
    sns_client = boto3.client('sns', region_name=region)
    subscriber_issues = []

    for topic_arn in sns_topics:
        try:
            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
            for subscription in subscriptions.get('Subscriptions', []):
                if subscription['Protocol'] not in ['https', 'sqs', 'lambda']:
                    subscriber_issues.append(topic_arn)
                    logger.warning(f"Topic {topic_arn} has inappropriate subscriber: {subscription['Endpoint']} with protocol {subscription['Protocol']}")
        except Exception as e:
            logger.error(f"Error listing subscriptions for topic {topic_arn}: {str(e)}")

    return subscriber_issues

def check_sns_public_access():
    sns_client = boto3.client('sns', region_name=region)
    public_access_issues = []

    for topic_arn in sns_topics:
        try:
            attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)
            policy = json.loads(attributes['Attributes'].get('Policy', '{}'))
            if any(statement.get('Effect') == 'Allow' and '*' in statement.get('Principal', {}).get('AWS', []) for statement in policy.get('Statement', [])):
                public_access_issues.append(topic_arn)
                logger.warning(f"Topic {topic_arn} is publicly accessible.")
        except Exception as e:
            logger.error(f"Error getting attributes for topic {topic_arn}: {str(e)}")

    return public_access_issues

def check_sns_encryption():
    sns_client = boto3.client('sns', region_name=region)
    encryption_issues = []

    for topic_arn in sns_topics:
        try:
            attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)
            if 'KmsMasterKeyId' not in attributes['Attributes']:
                encryption_issues.append(topic_arn)
                logger.warning(f"Topic {topic_arn} is not encrypted with a KMS Customer Master Key.")
        except Exception as e:
            logger.error(f"Error getting attributes for topic {topic_arn}: {str(e)}")

    return encryption_issues

def check_sns_cross_account_access():
    sns_client = boto3.client('sns', region_name=region)
    cross_account_issues = []

    for topic_arn in sns_topics:
        try:
            attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)
            policy = json.loads(attributes['Attributes'].get('Policy', '{}'))
            for statement in policy.get('Statement', []):
                if statement.get('Effect') == 'Allow' and statement.get('Principal', {}).get('AWS', '*') != '*':
                    cross_account_issues.append(topic_arn)
                    logger.warning(f"Topic {topic_arn} allows cross-account access.")
        except Exception as e:
            logger.error(f"Error getting attributes for topic {topic_arn}: {str(e)}")

    return cross_account_issues

def check_sns_secure_connections():
    sns_client = boto3.client('sns', region_name=region)
    insecure_connection_issues = []

    for topic_arn in sns_topics:
        try:
            attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)
            policy = json.loads(attributes['Attributes'].get('Policy', '{}'))
            for statement in policy.get('Statement', []):
                if statement.get('Effect') == 'Allow' and 'http' in statement.get('Condition', {}).get('StringLike', {}).get('aws:SourceArn', ''):
                    insecure_connection_issues.append(topic_arn)
                    logger.warning(f"Topic {topic_arn} does not enforce secure connections.")
        except Exception as e:
            logger.error(f"Error getting attributes for topic {topic_arn}: {str(e)}")

    return insecure_connection_issues

def check_sns_vpc_endpoint():
    sns_client = boto3.client('sns', region_name=region)
    ec2_client = boto3.client('ec2', region_name=region)
    vpc_endpoint_issues = []

    vpc_endpoints = ec2_client.describe_vpc_endpoints(Filters=[{'Name': 'service-name', 'Values': ['com.amazonaws.sns']}])

    for topic_arn in sns_topics:
        try:
            attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)
            vpc_endpoint_ids = attributes['Attributes'].get('VpcEndpointIds', '').split(',')
            for vpc_endpoint_id in vpc_endpoint_ids:
                if vpc_endpoint_id not in [ep['VpcEndpointId'] for ep in vpc_endpoints['VpcEndpoints']]:
                    vpc_endpoint_issues.append(topic_arn)
                    logger.warning(f"Topic {topic_arn} is not connected to a valid VPC endpoint.")
        except Exception as e:
            logger.error(f"Error getting VPC endpoint attributes for topic {topic_arn}: {str(e)}")

    return vpc_endpoint_issues