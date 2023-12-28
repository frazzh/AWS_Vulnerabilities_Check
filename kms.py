import boto3
import json

# Text file path
txt_file_path = 'Vulnerability_Check_Results.txt'
boto3_client = boto3.client('kms')
count = 0


def write_to_txt(message):
    with open(txt_file_path, 'a') as txtfile:
        txtfile.write(f"{message}\n")


def check_kms_vulnerabilities():
    global count
    # Initialize the KMS client
    kms_client = boto3.client('kms')

    write_to_txt("\nKMS Vulnerability Check Results:\n")

    # List all KMS keys
    keys_response = kms_client.list_keys()

    for key in keys_response['Keys']:
        key_id = key['KeyId']

        # Get key rotation status
        rotation_response = kms_client.get_key_rotation_status(KeyId=key_id)
        rotation_enabled = rotation_response['KeyRotationEnabled']
        if not rotation_enabled:
            count += 1

        # Get key policy
        policy_response = kms_client.get_key_policy(
            KeyId=key_id,
            PolicyName='default'
        )
        key_policy = json.loads(policy_response['Policy'])

        # Check for overly permissive key policies
        overly_permissive_warning = ""
        for statement in key_policy.get('Statement', []):
            if statement.get('Effect') == 'Allow' and 'Principal' in statement:
                principal_value = statement['Principal'].get('AWS', '')
                if principal_value == '*':
                    count += 1
                    overly_permissive_warning = "Overly permissive key policy with Principal set to '*'"

        # Write results to text file
        write_to_txt(f"Key ID: {key_id}")
        write_to_txt(f"{'Key Rotation Enabled'if rotation_enabled else '[Vulnerability] Key Rotation Disabled'}")
        write_to_txt(f"[Vulnerability] Overly Permissive Warning: {overly_permissive_warning}")


def run():
    check_kms_vulnerabilities()
    write_to_txt(f'{count - 1} vulnerabilities found\n')
    print(f'KMS Checks Completed')
