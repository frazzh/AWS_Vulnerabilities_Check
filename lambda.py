import json
import boto3
from datetime import datetime, timedelta, timezone

iam = boto3.client('iam')
s3 = boto3.client('s3')
cloudtrail = boto3.client('cloudtrail')


class S3Writer:
    def __init__(self):
        self.content_buffer = []

    def append_content(self, text):
        if self.content_buffer:
            self.content_buffer.append('\n')
        self.content_buffer.append(text)

    def write_to_s3(self, bucket_name, file_name):
        s3 = boto3.client('s3')
        final_content = ''.join(self.content_buffer)
        s3.put_object(Body=final_content, Bucket=bucket_name, Key=file_name)

        return {
            'statusCode': 200,
            'body': json.dumps('Hello from Lambda!')
        }


s3_writer = S3Writer()
count = 0


def detect_mfa():
    global count
    flag = 0
    try:
        response = iam.list_users()
        users = response['Users']

        for user in users:
            response = iam.list_mfa_devices(UserName=user['UserName'])
            mfa_devices = response['MFADevices']

            if not mfa_devices:
                count += 1
                flag = 1
                s3_writer.append_content(
                    f'[Vulnerability] Multi-factor authentication is not enabled for user {user["UserName"]}.')
        if flag == 0:
            s3_writer.append_content('MFA is enabled for all users.')

    except Exception as e:
        s3_writer.append_content(f'Error: {e}')


def detect_root_account_credentials():
    global count
    try:
        flag = 0
        response = cloudtrail.lookup_events(LookupAttributes=[
            {
                'AttributeKey': 'EventName',
                'AttributeValue': 'ConsoleLogin'
            },
        ],
            StartTime=datetime.now() - timedelta(days=60)
        )
        events = response['Events']

        for event in events:
            if event['Username'] == 'root':
                count += 1
                s3_writer.append_content('[Vulnerability] The AWS root account was used to log in recently.')
                flag = 1
                break
        if flag == 0:
            s3_writer.append_content('Root account has not been used to log in recently.')

    except Exception as e:
        s3_writer.append_content(f'Error: {e}')


def detect_inadequate_password_policy():
    global count
    try:
        response = iam.get_account_password_policy()
        password_policy = response['PasswordPolicy']
        if not password_policy:
            count += 1
            s3_writer.append_content('[Vulnerability] Headsup! No custom password policy set.')

        if password_policy['MinimumPasswordLength'] < 12:
            s3_writer.append_content('The minimum password length is less than 12 characters.')

        if not password_policy['RequireSymbols']:
            s3_writer.append_content('The password policy does not require symbols.')

        if not password_policy['RequireNumbers']:
            s3_writer.append_content('The password policy does not require numbers.')

        if not password_policy['RequireUppercaseCharacters']:
            s3_writer.append_content('The password policy does not require uppercase characters.')

        if not password_policy['RequireLowercaseCharacters']:
            s3_writer.append_content('The password policy does not require lowercase characters.')

    except iam.exceptions.NoSuchEntityException:
        count += 1
        s3_writer.append_content('[Vulnerability] Headsup! No custom password policy set.')
    except Exception as e:
        s3_writer.append_content(f'Error: {e}')


def detect_policy_admin_permissions():
    global count
    try:
        flag = 0
        response = iam.list_policies(Scope='Local')
        policies = response['Policies']

        for policy in policies:
            policy_response = iam.get_policy(PolicyArn=policy['Arn'])
            policy_version = policy_response['Policy']['DefaultVersionId']
            policy_response = iam.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy_version)
            policy_document = policy_response['PolicyVersion']['Document']

            if '"Effect": "Allow", "Action": "*", "Resource": "*"' in policy_document:
                flag = 1
                count += 1
                s3_writer.append_content(f'[Vulnerability] Policy {policy["PolicyName"]} grants unrestricted access.')
        if flag == 0:
            s3_writer.append_content('No customer managed policy has admin permissions')

    except Exception as e:
        s3_writer.append_content(f'Error: {e}')


def detect_overprivileged_roles():
    global count
    try:
        response = iam.list_roles()
        roles = response['Roles']

        for role in roles:
            response = iam.list_attached_role_policies(RoleName=role['RoleName'])
            policies = response['AttachedPolicies']

            for policy in policies:
                if 'AdministratorAccess' in policy['PolicyName']:
                    count += 1
                    s3_writer.append_content(f'[Vulnerability] The role {role["RoleName"]} has administrator access.')

    except Exception as e:
        s3_writer.append_content(f'Error: {e}')


def detect_overprivileged_groups():
    global count
    try:
        response = iam.list_groups()
        groups = response['Groups']

        for group in groups:
            response = iam.list_attached_group_policies(GroupName=group['GroupName'])
            policies = response['AttachedPolicies']

            for policy in policies:
                if 'AdministratorAccess' in policy['PolicyName']:
                    count += 1
                    s3_writer.append_content(
                        f'[Vulnerability] The group {group["GroupName"]} has administrator access.')
    except Exception as e:
        s3_writer.append_content(f'Error: {e}')


def detect_recent_access_keys():
    global count
    try:
        response = iam.list_users()
        users = response['Users']
        current_time = datetime.now(timezone.utc)

        for user in users:
            response = iam.list_access_keys(UserName=user['UserName'])
            access_keys = response['AccessKeyMetadata']

            for access_key in access_keys:
                if access_key['Status'] == 'Active':
                    response = iam.get_access_key_last_used(AccessKeyId=access_key['AccessKeyId'])
                    last_used = response['AccessKeyLastUsed']['LastUsedDate']
                    if (current_time - last_used).days > 60:
                        count += 1
                        s3_writer.append_content(
                            f'[Vulnerability] The access key for user {user["UserName"]} has not been used recently.')

    except Exception as e:
        s3_writer.append_content(f'Error: {e}')


def detect_unaudited_permissions():
    global count
    try:
        response = iam.list_policies(Scope='Local')
        policies = response['Policies']
        flag = 0

        for policy in policies:
            if policy['CreateDate'].date() < (datetime.now() - timedelta(days=60)).date():
                flag = 1
                count += 1
                s3_writer.append_content(
                    f'[Vulnerability] The policy {policy["PolicyName"]} has not been updated recently.')
        if flag == 0:
            s3_writer.append_content('No outdated policies')

    except Exception as e:
        s3_writer.append_content(f'Error: {e}')


def lambda_handler(event, context):
    bucket_name = 'awsvulnerabilities'
    file_name = 'AWS_Vulnerability_Results.txt'

    # IAM
    detect_access_management_console()
    detect_mfa()
    detect_root_account_credentials()
    detect_inadequate_password_policy()
    detect_policy_admin_permissions()
    detect_overprivileged_roles()
    detect_overprivileged_groups()
    detect_recent_access_keys()
    detect_unaudited_permissions()

    # S3

    print(f'IAM Checks Completed')
    s3_writer.append_content(f'{count} Vulnerabilities found')
    return s3_writer.write_to_s3(bucket_name, file_name)
