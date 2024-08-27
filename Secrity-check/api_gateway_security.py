import boto3
import json
import os
from botocore.exceptions import ClientError

# Get region and account ID from environment variables
region = os.environ['region']
account_id = os.environ['accountid']
api_id = os.environ['Var_api_gateway_list'].split(',')

def get_api_gateway_client(region_name):
    return boto3.client('apigateway', region_name=region_name)


def check_waf_configuration(api_id, region):
    waf_client = boto3.client('wafv2', region_name=region)
    try:
        waf_resp = waf_client.list_web_acls(Scope='REGIONAL')
        associated_resources = []

        for acl in waf_resp['WebACLs']:
            web_acl_arn = acl['ARN']
            resources = waf_client.list_resources_for_web_acl(WebACLArn=web_acl_arn, ResourceType='API_GATEWAY')
            for resource in resources['ResourceArns']:
                if api_id in resource:
                    associated_resources.append(web_acl_arn)

        return {
            'WAFAssociated': bool(associated_resources),
            'AssociatedACLs': associated_resources
        }
    except ClientError as e:
        return {'Error': str(e)}


def check_throttling_settings(api_id, region):
    if not api_id:
        return {'Error': 'API ID is None'}
    client = get_api_gateway_client(region)
    try:
        response = client.get_stage(restApiId=api_id, stageName='stg')  # Adjust 'stg' to your stage name
        throttling = response['methodSettings']['*/*'].get('throttlingRateLimit', 'Not Set')
        return {'ThrottlingRateLimit': throttling}
    except ClientError as e:
        return {'Error': str(e)}
    except ParamValidationError as e:
        return {'Error': str(e)}


def check_authentication_and_authorization(api_id, region):
    if not api_id:
        return {'Error': 'API ID is None'}
    client = get_api_gateway_client(region)
    try:
        authorizers = client.get_authorizers(restApiId=api_id)
        auth_details = [{auth['id']: auth.get('type', 'None')} for auth in authorizers['items']]
        return auth_details
    except ClientError as e:
        return {'Error': str(e)}
    except ParamValidationError as e:
        return {'Error': str(e)}

def check_tls_version(api_id, region):
    if not api_id:
        return {'Error': 'API ID is None'}
    client = get_api_gateway_client(region)
    try:
        domain_names = client.get_domain_names()
        associated_domains = []

        for domain in domain_names['items']:
            try:
                mappings = client.get_base_path_mappings(domainName=domain['domainName'])
                for mapping in mappings.get('items', []):
                    if mapping['restApiId'] == api_id:
                        domain_details = client.get_domain_name(domainName=domain['domainName'])
                        associated_domains.append({
                            'domainName': domain['domainName'],
                            'certificateArn': domain.get('regionalCertificateArn', 'None'),
                            'tlsVersion': domain_details.get('securityPolicy', 'TLS_1.2')
                        })
            except KeyError:
                continue

        return {'SSLCertificates': associated_domains}
    except ClientError as e:
        return {'Error': str(e)}
    except ParamValidationError as e:
        return {'Error': str(e)}

def check_tracing_enabled(api_id, region):
    if not api_id:
        return {'Error': 'API ID is None'}
    client = get_api_gateway_client(region)
    try:
        response = client.get_stage(restApiId=api_id, stageName='stg')  # Adjust 'stg' to your stage name
        tracing_enabled = response.get('tracingEnabled', False)
        return {'TracingEnabled': tracing_enabled}
    except ClientError as e:
        return {'Error': str(e)}
    except ParamValidationError as e:
        return {'Error': str(e)}

def check_cloudwatch_metrics(api_id, region):
    if not api_id:
        return {'Error': 'API ID is None'}
    client = get_api_gateway_client(region)
    try:
        response = client.get_stage(restApiId=api_id, stageName='stg')
        metrics_enabled = response['methodSettings']['*/*'].get('metricsEnabled', False)
        return f"CloudWatch Metrics Enabled: {metrics_enabled}"
    except ClientError as e:
        return f"Error checking CloudWatch metrics: {str(e)}"
    except ParamValidationError as e:
        return f"Error checking CloudWatch metrics: {str(e)}"

def check_private_api_access(api_id, region):
    if not api_id:
        return {'Error': 'API ID is None'}
    client = get_api_gateway_client(region)
    try:
        response = client.get_rest_api(restApiId=api_id)
        endpoint_type = response.get('endpointConfiguration', {}).get('types', [])
        if 'PRIVATE' in endpoint_type:
            return "API is private"
        else:
            return "API is not private"
    except ClientError as e:
        return f"Error checking API access type: {str(e)}"
    except ParamValidationError as e:
        return f"Error checking API access type: {str(e)}"

def check_cache_encryption(api_id, region):
    if not api_id:
        return {'Error': 'API ID is None'}
    client = get_api_gateway_client(region)
    try:
        response = client.get_stage(restApiId=api_id, stageName='stg')
        cache_encryption_enabled = response['methodSettings']['*/*'].get('cacheDataEncrypted', False)
        return f"Cache Encryption Enabled: {cache_encryption_enabled}"
    except ClientError as e:
        return f"Error checking cache encryption: {str(e)}"
    except ParamValidationError as e:
        return f"Error checking cache encryption: {str(e)}"

def check_validations(api_id, region):
    if not api_id:
        return {'Error': 'API ID is None'}
    client = get_api_gateway_client(region)
    try:
        validators = client.get_request_validators(restApiId=api_id)
        if validators['items']:
            return "Request validators are configured"
        else:
            return "No request validators configured"
    except ClientError as e:
        return f"Error checking request validators: {str(e)}"
    except ParamValidationError as e:
        return f"Error checking request validators: {str(e)}"


def check_security_headers(api_id, region):
    if not api_id:
        return {'Error': 'API ID is None'}
    client = get_api_gateway_client(region)
    headers_to_check = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection'
    ]

    try:
        # List all resources
        resources = client.get_resources(restApiId=api_id)
        for resource in resources['items']:
            for method in resource.get('resourceMethods', {}).keys():
                try:
                    # Get method response
                    method_response = client.get_method_response(
                        restApiId=api_id,
                        resourceId=resource['id'],
                        httpMethod=method,
                        statusCode='200'  # Check for status code 200, can be adjusted
                    )
                    
                    # Check headers in method response
                    method_response_headers = method_response.get('responseParameters', {})
                    for header in headers_to_check:
                        if f'method.response.header.{header}' not in method_response_headers:
                            return f"Header {header} not found in method response for resource {resource['path']} and method {method}"

                    # Get integration response
                    integration_response = client.get_integration_response(
                        restApiId=api_id,
                        resourceId=resource['id'],
                        httpMethod=method,
                        statusCode='200'  # Check for status code 200, can be adjusted
                    )
                    
                    # Check headers in integration response
                    integration_response_headers = integration_response.get('responseParameters', {})
                    for header in headers_to_check:
                        if f'integration.response.header.{header}' not in integration_response_headers:
                            return f"Header {header} not found in integration response for resource {resource['path']} and method {method}"

                except ClientError as e:
                    return f"Error checking security headers for resource {resource['path']} and method {method}: {str(e)}"

        return "All required security headers are present in method and integration responses"
    except ClientError as e:
        return f"Error checking security headers: {str(e)}"
    except ParamValidationError as e:
        return f"Error checking security headers: {str(e)}"

def check_logging_enabled(api_id, region):
    if not api_id:
        return {'Error': 'API ID is None'}
    client = get_api_gateway_client(region)
    try:
        response = client.get_stage(restApiId=api_id, stageName='stg')
        logging_enabled = response['methodSettings']['*/*'].get('loggingLevel', None)
        return f"Logging Enabled: {bool(logging_enabled)}"
    except ClientError as e:
        return f"Error checking logging settings: {str(e)}"
    except ParamValidationError as e:
        return f"Error checking logging settings: {str(e)}"

def check_resource_policies(api_id, region):
    if not api_id:
        return {'Error': 'API ID is None'}
    client = get_api_gateway_client(region)
    try:
        response = client.get_rest_api(restApiId=api_id)
        policy = response.get('policy', None)
        return f"Resource Policy Attached: {bool(policy)}"
    except ClientError as e:
        return f"Error checking resource policies: {str(e)}"
    except ParamValidationError as e:
        return f"Error checking resource policies: {str(e)}"

