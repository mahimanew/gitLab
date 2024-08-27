import boto3
import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

region = os.environ['region']
account_id = os.environ['accountid']

# Ensure the environment variable 'Var_sqs_list' is set
sqs_list = os.environ.get('Var_sqs_list')
if sqs_list:
    sqs_list = sqs_list.split(',')
else:
    sqs_list = []
    logger.warning("Environment variable 'Var_sqs_list' is not set. No SQS LIST to check.")

def dlq_check_function():
    sqs = boto3.client('sqs')
    queues = sqs.list_queues()

    dlq_issues = []

    for queue_url in queues.get('QueueUrls', []):
        try:
            response = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=['RedrivePolicy']
            )
            if 'Attributes' not in response or 'RedrivePolicy' not in response['Attributes']:
                dlq_issues.append(queue_url)
                logger.warning(f"Queue {queue_url} does not have a DLQ configured.")
        except sqs.exceptions.QueueDoesNotExist:
            logger.error(f"Queue {queue_url} does not exist.")
        except Exception as e:
            logger.error(f"Error getting DLQ attributes for queue {queue_url}: {str(e)}")

    return dlq_issues

def identify_admin_access_function_sqs():
    sqs = boto3.client('sqs')
    queues = sqs.list_queues()

    admin_access_issues = []

    for queue_url in queues.get('QueueUrls', []):
        try:
            response = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=['Policy']
            )
            if 'Attributes' in response and 'Policy' in response['Attributes']:
                queue_policy = json.loads(response['Attributes']['Policy'])
                if any(statement.get('Effect') == 'Allow' and '*' in statement.get('Principal', {}).get('AWS', []) for statement in queue_policy.get('Statement', [])):
                    admin_access_issues.append(queue_url)
                    logger.warning(f"Queue {queue_url} is exposed to everyone.")
            else:
                logger.warning(f"Queue {queue_url} does not have 'Attributes' or 'Policy'.")
        except sqs.exceptions.QueueDoesNotExist:
            logger.error(f"Queue {queue_url} does not exist.")
        except Exception as e:
            logger.error(f"Error getting attributes for queue {queue_url}: {str(e)}")

    return admin_access_issues

def cross_account_function_sqs():
    sqs = boto3.client('sqs')
    queues = sqs.list_queues()

    cross_account_issues = []

    for queue_url in queues.get('QueueUrls', []):
        try:
            response = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=['Policy']
            )
            if 'Attributes' in response and 'Policy' in response['Attributes']:
                queue_policy = json.loads(response['Attributes']['Policy'])
                for statement in queue_policy.get('Statement', []):
                    if statement.get('Effect') == 'Allow' and statement.get('Principal', {}).get('AWS', '*') != '*':
                        cross_account_issues.append(queue_url)
                        logger.warning(f"Queue {queue_url} allows cross-account access.")
            else:
                logger.warning(f"Queue {queue_url} does not have 'Attributes' or 'Policy'.")
        except sqs.exceptions.QueueDoesNotExist:
            logger.error(f"Queue {queue_url} does not exist.")
        except Exception as e:
            logger.error(f"Error getting attributes for queue {queue_url}: {str(e)}")

    return cross_account_issues

def kms_sqs():
    sqs_client = boto3.client('sqs')
    kms_issues = []

    try:
        queues = sqs_client.list_queues()

        for queue_url in queues.get('QueueUrls', []):
            try:
                response = sqs_client.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=['KmsMasterKeyId']
                )
                if 'Attributes' not in response or 'KmsMasterKeyId' not in response['Attributes']:
                    kms_issues.append(queue_url)
                    logger.warning(f"Queue {queue_url} is not encrypted with a KMS Customer Master Key.")
            except sqs_client.exceptions.QueueDoesNotExist:
                logger.error(f"Queue {queue_url} does not exist.")
            except Exception as e:
                logger.error(f"Error getting attributes for queue {queue_url}: {str(e)}")
    except Exception as e:
        logger.error(f"Error listing queues: {str(e)}")

    return kms_issues

def sqs_security_checks():
    return {
        'DLQ Check': dlq_check_function(),
        'No Public Access': identify_admin_access_function_sqs(),
        'Cross Account Access': cross_account_function_sqs(),
        'Custom KMS Key Attached': kms_sqs()
    }
