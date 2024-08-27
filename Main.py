import json
import logging
import os
from lambda_security import vpc_function
from lambda_security import log_group_function
from lambda_security import tracing_function
from lambda_security import cross_acccount_function
from lambda_security import unique_role_function
from lambda_security import encript_custom_KMS_function
from lambda_security import identify_admin_access_function
# from lambda_security import identify_resource_based_policy_function
# from sqs_security import dlq_check_function
# from sqs_security import identify_admin_access_function_sqs
# from sqs_security import cross_account_function_sqs
# from sqs_security import kms_sqs
# from dynamodb_security import check_table_encryption
# from dynamodb_security import check_vpce_in_IAM_role
# from dynamodb_security import check_IAM_least_permission
# from dynamodb_security import check_streams
# from api_gateway_security import check_waf_configuration #done
# from api_gateway_security import check_throttling_settings #done
# from api_gateway_security import check_authentication_and_authorization  #done
# from api_gateway_security import check_cloudwatch_metrics
# from api_gateway_security import check_private_api_access
# from api_gateway_security import check_cache_encryption
# from api_gateway_security import check_validations
# from api_gateway_security import check_security_headers
# from api_gateway_security import check_tls_version #done
# from api_gateway_security import check_tracing_enabled #done
# from api_gateway_security import check_logging_enabled
# from api_gateway_security import check_resource_policies

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler():
    Json_string_lambda = json.dumps({   
                                'VPC': vpc_function(),
                                'log group' : log_group_function(),
                                'Enable Active tracing' : tracing_function(),
                                'No Cross account' : cross_acccount_function(),
                                'Unique role assigned' : unique_role_function(),
                                'custom_kms_key_for_EV' :  encript_custom_KMS_function(),
                                "identify_admin_access_function" : identify_admin_access_function(),
                                "identify_resource_based_policy_function" : identify_resource_based_policy_function()
                                })
    
    print(Json_string_lambda)
    print("Completed..")


    # Json_string_sqs = json.dumps({
    #                     'DLQ Check' : dlq_check_function(),
    #                     '* access' : identify_admin_access_function_sqs(),
    #                     'Cross Account access' : cross_account_function_sqs(),
    #                     'Custom kms key attached' : kms_sqs()
    #                     })
    # print(Json_string_sqs)

    # Json_string_DynamoDB = json.dumps({
    #                     'Encription' : check_table_encryption(),
    #                     'Check Least Permission' : check_IAM_least_permission(),
    #                     'check_vpce_in_IAM_role' : check_vpce_in_IAM_role(),
    #                     'check_streams' : check_streams()
    #                     })
    # print(Json_string_DynamoDB)

# def lambda_handler(event, context):
#     api_id = event.get('api_id', os.environ.get('Var_api_gateway_list'))
#     region = event.get('region', os.environ.get('region'))
    
#     if not api_id or api_id == 'Var_api_gateway_list':
#         print(f"Invalid API ID: {api_id}")
#         return {'Error': 'Invalid or missing API Gateway ID'}

#     print(f"API ID: {api_id}, Region: {region}")

#     results = {
#         'WAF Configuration': check_waf_configuration(api_id, region),
#         'Throttling Settings': check_throttling_settings(api_id, region),
#         'Authentication and Authorization': check_authentication_and_authorization(api_id, region),
#         'TLS Version': check_tls_version(api_id, region),
#         'Tracing Enabled': check_tracing_enabled(api_id, region),
#         'CloudWatch Metrics': check_cloudwatch_metrics(api_id, region),
#         'Private API Access': check_private_api_access(api_id, region),
#         'Cache Encryption': check_cache_encryption(api_id, region),
#         'Validations Configured': check_validations(api_id, region),
#         'Security Headers': check_security_headers(api_id, region),
#         'Logging Enabled': check_logging_enabled(api_id, region),
#         'Resource Policies': check_resource_policies(api_id, region)
#     }
    
    return json.dumps(results, indent=4)

if __name__ == "__main__":
    api_id = os.environ.get('Var_api_gateway_list')
    region = os.environ.get('region')
    
    if not api_id or api_id == 'Var_api_gateway_list':
        print(f"API Gateway ID is not set correctly: {api_id}")
    else:
        event = {
            'api_id': api_id,
            'region': region
        }
        context = None
        print(lambda_handler(event, context))

