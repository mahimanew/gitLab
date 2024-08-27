import boto3
import json
import os
from botocore.exceptions import ClientError

# Environment variables
region = os.environ['region']
account_id = os.environ['accountid']
table_list = os.environ['Var_dynamodb_list'].split(',')
role_list = os.environ['Var_role_list'].split(',')

def check_iam_least_privilege():
    iam_client = boto3.client('iam', region_name=region)
    issues = []
    
    for role_name in role_list:
        try:
            response = iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in response['AttachedPolicies']:
                policy_name = policy['PolicyName']
                if policy_name == 'AdministratorAccess' or 'full' in policy_name:
                    issues.append({role_name: f"Role contains full or admin access: {policy_name}"})
                else:
                    policy_arn = f'arn:aws:iam::{account_id}:policy/{policy_name}'
                    policy_document_response = iam_client.get_policy(PolicyArn=policy_arn)
                    version_id = policy_document_response['Policy']['DefaultVersionId']
                    policy_version_response = iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=version_id
                    )
                    policy_document = policy_version_response['PolicyVersion']['Document']
                    for statement in policy_document['Statement']:
                        if 'Action' in statement:
                            actions = statement['Action']
                            if isinstance(actions, str):
                                actions = [actions]
                            if any('*' in action for action in actions):
                                issues.append({role_name: f"Policy contains wildcard actions: {policy_name}"})
        except iam_client.exceptions.NoSuchEntityException:
            issues.append({role_name: "Role does not exist"})
        except ClientError as e:
            issues.append({role_name: str(e)})
    
    return issues

def check_table_encryption():
    dynamodb = boto3.client('dynamodb', region_name=region)
    issues = []

    for table_name in table_list:
        try:
            response = dynamodb.describe_table(TableName=table_name)
            if 'SSEDescription' not in response['Table'] or response['Table']['SSEDescription'].get('Status') != 'ENABLED':
                issues.append({table_name: "Not encrypted"})
        except dynamodb.exceptions.ResourceNotFoundException:
            issues.append({table_name: "Table does not exist"})
        except ClientError as e:
            issues.append({table_name: str(e)})
    
    return issues

def check_vpc_endpoint():
    ec2 = boto3.client('ec2', region_name=region)
    issues = []

    vpc_endpoints = ec2.describe_vpc_endpoints(Filters=[{'Name': 'service-name', 'Values': ['com.amazonaws.dynamodb']}])
    if not vpc_endpoints['VpcEndpoints']:
        issues.append("No VPC endpoint for DynamoDB found")
    
    return issues

def check_fine_grained_access_control():
    iam_client = boto3.client('iam', region_name=region)
    issues = []

    for role_name in role_list:
        try:
            response = iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in response['AttachedPolicies']:
                policy_name = policy['PolicyName']
                policy_arn = f'arn:aws:iam::{account_id}:policy/{policy_name}'
                policy_document_response = iam_client.get_policy(PolicyArn=policy_arn)
                version_id = policy_document_response['Policy']['DefaultVersionId']
                policy_version_response = iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version_id
                )
                policy_document = policy_version_response['PolicyVersion']['Document']
                for statement in policy_document['Statement']:
                    if 'Condition' not in statement or 'dynamodb:LeadingKeys' not in statement['Condition']:
                        issues.append({role_name: f"Policy lacks fine-grained access control: {policy_name}"})
        except iam_client.exceptions.NoSuchEntityException:
            issues.append({role_name: "Role does not exist"})
        except ClientError as e:
            issues.append({role_name: str(e)})
    
    return issues

def check_dynamodb_streams():
    dynamodb = boto3.client('dynamodb', region_name=region)
    issues = []

    for table_name in table_list:
        try:
            response = dynamodb.describe_table(TableName=table_name)
            if 'LatestStreamArn' not in response['Table']:
                issues.append({table_name: "Streams are not enabled"})
        except dynamodb.exceptions.ResourceNotFoundException:
            issues.append({table_name: "Table does not exist"})
        except ClientError as e:
            issues.append({table_name: str(e)})
    
    return issues

def check_data_sanitization_and_validation():
    issues = []
    # This would typically involve checking Lambda functions or other processes
    # Here, we just provide a placeholder to demonstrate where such logic would go
    issues.append("Check data sanitization and validation processes manually")
    
    return issues

def check_lambda_and_step_functions():
    lambda_client = boto3.client('lambda', region_name=region)
    stepfunctions_client = boto3.client('stepfunctions', region_name=region)
    issues = []

    try:
        lambdas = lambda_client.list_functions()
        step_functions = stepfunctions_client.list_state_machines()
        if not lambdas['Functions']:
            issues.append("No Lambda functions found for data ingestion")
        if not step_functions['stateMachines']:
            issues.append("No Step Functions found for data processing")
    except ClientError as e:
        issues.append(str(e))
    
    return issues

def check_cloudwatch_metrics_and_alarms():
    cloudwatch = boto3.client('cloudwatch', region_name=region)
    issues = []

    try:
        alarms = cloudwatch.describe_alarms()
        if not alarms['MetricAlarms']:
            issues.append("No CloudWatch Alarms found for DynamoDB monitoring")
    except ClientError as e:
        issues.append(str(e))
    
    return issues


    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()
