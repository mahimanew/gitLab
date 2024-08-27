import boto3
import json
import os
from botocore.exceptions import ClientError

region = os.environ['region']
account_id = os.environ['accountid']

lambda_list = os.environ['Var_lambda_list'].split(',')
def vpc_function():
    
    lambda_client = boto3.client('lambda',region_name=region) 
                               
    ec2_client = boto3.client('ec2', region_name=region)                                
    
    vpc_function_names = []
    

    for function_name in lambda_list:
        print('_________________________',type(function_name))
        response = lambda_client.get_function_configuration(FunctionName=function_name)
        if 'VpcConfig' in response:
            vpc_config = response['VpcConfig']
            vpc_id = vpc_config.get('VpcId')
            count = 0
            subnet_ids = vpc_config.get('SubnetIds', [])
            for subnet_id in subnet_ids:
                response = ec2_client.describe_subnets(SubnetIds=[subnet_id])
                subnet_name = None
                subnet_info = response['Subnets'][0]  
                for tag in subnet_info['Tags']:
                    if tag['Key'] == 'Name':
                        subnet_name = tag['Value']
                        if subnet_name.lower().__contains__('private'):
                            count = count + 1
                            if count == 3:
                                vpc_function_names.append({function_name : "Passed"})    
                        else:
                            vpc_function_names.append({function_name : "Lambda should be created within private subnet"} )        
        else:
            vpc_function_names.append({function_name : "It is not inside VPC"} )
    
    return vpc_function_names    
   


def log_group_function():
    logs_client = boto3.client('logs', region_name=region) 
    loggroup_function_names = []

    for function_name in lambda_list:
        
        try:
            response = logs_client.describe_log_streams(
                            logGroupName=f"/aws/lambda/{function_name}",
                            limit=1)
            
            if not response.get('logStreams'):
                loggroup_function_names.append({function_name : " log group is  empty."})
            else:
                loggroup_function_names.append({function_name : "Passed"})
        except:
            loggroup_function_names.append({function_name : "No log group"})
        
            
    return loggroup_function_names




def tracing_function():
    lambda_client = boto3.client('lambda', region_name=region) 
    tracing_function_names = []

    for function_name in lambda_list:
        response = lambda_client.get_function_configuration(FunctionName=function_name)
        if response.get('TracingConfig').get('Mode') == 'Active':
            tracing_function_names.append({function_name : "Passed"})
        if response.get('TracingConfig').get('Mode') == 'PassThrough':
            tracing_function_names.append({function_name : "Tracing not enabled"}) 
            
    return tracing_function_names



def cross_acccount_function():
    lambda_client = boto3.client('lambda', region_name=region)
    iam_client = boto3.client('iam', region_name=region)
    lambdas = os.environ.get('Var_lambda_list')    
    cross_account_access_function_names = []

    for function_name in lambda_list:
        response = lambda_client.get_function_configuration(FunctionName=function_name)
        execution_role_arn = response['Role']        
        role_response = iam_client.get_role(RoleName=execution_role_arn.split('/')[-1])
        trust_policy = role_response['Role']['AssumeRolePolicyDocument']
        if 'AWS' in trust_policy['Statement'][0]['Principal']:
            principals = trust_policy['Statement'][0]['Principal']['AWS']
            if isinstance(principals, list):
                for principal in principals:
                    if ':' in principal and principal.split(':')[4] != account_id:
                        cross_account_access_function_names.append({function_name : "Cross Account allowed"})
                        break;
            elif isinstance(principals, str):
                if ':' in principals and principals.split(':')[4] != account_id:
                    cross_account_access_function_names.append({function_name : "Cross Account allowed"})
        else:    
            cross_account_access_function_names.append({function_name : "Passed"})        
    return cross_account_access_function_names


def unique_role_function():
    unique_role_function_names = []
    lambda_client = boto3.client('lambda', region_name=region)
    for function_name in lambda_list:
        response = lambda_client.get_function_configuration(FunctionName=function_name)
        execution_role_arn = response['Role']
        if execution_role_arn:
            unique_role_function_names.append({function_name : "Passed"})
        else:
            unique_role_function_names.append({function_name : "No unique role"})
    return unique_role_function_names
    
    
def encript_custom_KMS_function():
    encript_custom_KMS_key = []
    lambda_client = boto3.client('lambda', region_name=region)
    for function_name in lambda_list:
        response = lambda_client.get_function_configuration(FunctionName=function_name)
        try:
            env_var = response['Environment']['Variables']
            if env_var:
                try:
                    response['KMSKeyArn']
                    encript_custom_KMS_key.append({function_name : "Passed"})
                except:
                    print('no custom kms key attched')
                    encript_custom_KMS_key.append({function_name : "No custom kMS Key attched with env variable"})
        except:
            print('no env variable')
            encript_custom_KMS_key.append({function_name : "Passed"})
    return encript_custom_KMS_key
    
    
def identify_admin_access_function():
    admin_access_function = []
    lambda_client = boto3.client('lambda', region_name=region)
                               
    iam_client = boto3.client('iam', region_name=region)
                               
    for function_name in lambda_list:
        response = lambda_client.get_function_configuration(FunctionName=function_name)
        execution_role_arn = response['Role']
        response = iam_client.list_attached_role_policies(RoleName=execution_role_arn.split('/')[-1])
        for policy in response['AttachedPolicies']:
            policy_name = policy['PolicyName']
            if policy_name == 'AdministratorAccess':
                admin_access_function.append({function_name : "contains admin access"})
            if 'full' in policy_name:
                admin_access_function.append({function_name : "contains full access"})
                
            
            policy_arn = 'arn:aws:iam::'+account_id+':policy/'+policy_name
            policy_document_respponse = ''
            
            
            try:
                policy_document_respponse = iam_client.get_policy(PolicyArn=policy_arn)
                version_id = policy_document_respponse['Policy']['DefaultVersionId']
                response = iam_client.get_policy_version(
                                    PolicyArn=policy_arn,
                                    VersionId=version_id)
                policy_document = response['PolicyVersion']['Document']
                for statement in policy_document['Statement']:
                    if 'Action' in statement:
                        if isinstance(statement['Action'], str):
                            if '*' in statement['Action']:
                                admin_access_function.append({function_name : "contains * in policy"})
                            else:
                                admin_access_function.append({function_name : "passed"})
                        elif isinstance(statement['Action'], list):
                            for action in statement['Action']:
                                if '*' in action:
                                    admin_access_function.append({function_name : "contains * in policy"})
                                else:
                                    admin_access_function.append({function_name : "passed"})
            except:
                admin_access_function.append({function_name : "Aws managed policy attched"})
    return admin_access_function
    
    
    
def identify_resource_based_policy_function():
    resource_based_policy_funtion = []
    admin_access_function = []
    lambda_client = boto3.client('lambda', region_name=region)
                               
    for function_name in lambda_list:
        try:
            response = lambda_client.get_policy(FunctionName=function_name)      
            policy = response['Policy']
            resource_based_policy_funtion.append({function_name : "Passed"})
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':                
                resource_based_policy_funtion.append({function_name : "does not have a resource-based policy attached."})
            else:
                print("An error occurred:", e)
    return resource_based_policy_funtion


        
   
