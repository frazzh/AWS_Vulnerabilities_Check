from datetime import datetime, timedelta, timezone
import boto3

# Text file path
txt_file_path = 'Vulnerability_Check_Results.txt'

# Session Initialization
aws_console = boto3.session.Session(profile_name="default")
iam = aws_console.client('iam')
cloudtrail = aws_console.client('cloudtrail')
count = 0


def write_to_txt(message):
    with open(txt_file_path, 'a') as txtfile:
        txtfile.write(f"{message}\n")


def run():

    def detect_access_management_console():
        global count
        try:
            response = iam.list_users()
            users = response['Users']
            for each_user in users:
                response1 = iam.get_login_profile(UserName=each_user['UserName'])
                if response1:
                    count += 1
                    write_to_txt(
                        f'User {each_user["UserName"]} has unrestricted access to the AWS Management Console.')
                else:
                    write_to_txt("No user has access to the AWS management console")
        except Exception as e:
            write_to_txt(f'Error: {e}')

    def detect_mfa():
        global count
        try:
            response = iam.list_users()
            users = response['Users']

            for user in users:
                response = iam.list_mfa_devices(UserName=user['UserName'])
                mfa_devices = response['MFADevices']

                if not mfa_devices:
                    count += 1
                    write_to_txt(f'Multi-factor authentication is not enabled for user {user["UserName"]}.')
                else:
                    write_to_txt("MFA is enabled for all users and root account.")

        except Exception as e:
            write_to_txt(f'Error: {e}')

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
                StartTime=datetime.now() - timedelta(days=30)
            )
            events = response['Events']

            for event in events:
                if event['Username'] == 'root':
                    count += 1
                    write_to_txt('The AWS root account was used to log in.')
                    flag = 1
                    break
            if flag == 0:
                write_to_txt("Root account has not been used to log in for the last 30 days.")

        except Exception as e:
            write_to_txt(f'Error: {e}')

    def detect_inadequate_password_policy():
        global count
        try:
            response = iam.get_account_password_policy()
            password_policy = response['PasswordPolicy']
            if not password_policy:
                count += 1
                write_to_txt("Headsup! No custom password policy set.")

            if password_policy['MinimumPasswordLength'] < 12:
                write_to_txt('The minimum password length is less than 12 characters.')

            if not password_policy['RequireSymbols']:
                write_to_txt('The password policy does not require symbols.')

            if not password_policy['RequireNumbers']:
                write_to_txt('The password policy does not require numbers.')

            if not password_policy['RequireUppercaseCharacters']:
                write_to_txt('The password policy does not require uppercase characters.')

            if not password_policy['RequireLowercaseCharacters']:
                write_to_txt('The password policy does not require lowercase characters.')

        except iam.exceptions.NoSuchEntityException:
            count += 1
            write_to_txt("Headsup! No custom password policy set.")
        except Exception as e:
            write_to_txt(f'Error: {e}')

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
                    write_to_txt(f'Policy {policy["PolicyName"]} grants unrestricted access.')
            if flag == 0:
                write_to_txt("No customer managed policy has admin permissions")

        except Exception as e:
            write_to_txt(f'Error: {e}')

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
                        write_to_txt(f'The role {role["RoleName"]} has administrator access.')

        except Exception as e:
            write_to_txt(f'Error: {e}')

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
                        write_to_txt(f'The group {group["GroupName"]} has administrator access.')
        except Exception as e:
            write_to_txt(f'Error: {e}')

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
                        if (current_time - last_used).days < 30:
                            count += 1
                            write_to_txt(
                                f'The access key for user {user["UserName"]} is active and has been used recently.')
                        else:
                            write_to_txt(
                                f'Access key {access_key["AccessKeyId"]} has not been used for the last 30 days.')

        except Exception as e:
            write_to_txt(f'Error: {e}')

    def detect_unaudited_permissions():
        global count
        try:
            response = iam.list_policies(Scope='Local')
            policies = response['Policies']
            flag = 0

            for policy in policies:
                if policy['CreateDate'].date() < (datetime.now() - timedelta(days=90)).date():
                    flag = 1
                    count += 1
                    write_to_txt(f'The policy {policy["PolicyName"]} has not been updated in the last 90 days.')
            if flag == 0:
                write_to_txt('No outdated policies')

        except Exception as e:
            write_to_txt(f'Error: {e}')

    write_to_txt("\nIAM Vulnerability Check Results:\n")
    detect_access_management_console()
    detect_mfa()
    detect_root_account_credentials()
    detect_inadequate_password_policy()
    detect_policy_admin_permissions()
    detect_overprivileged_roles()
    detect_overprivileged_groups()
    detect_recent_access_keys()
    detect_unaudited_permissions()
    write_to_txt(f'{count} vulnerabilities found')

    print(f'IAM Checks Completed')
