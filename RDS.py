from datetime import datetime, timedelta, timezone
import boto3

aws_console = boto3.session.Session(profile_name="default")
rds = aws_console.client('rds')

output_file = 'Vulnerability_Check_Results.txt'

count = 0


def check_rds_encryption_status(instance):
    global count
    with open(output_file, 'a') as output:
        instance_identifier = instance['DBInstanceIdentifier']
        encryption_at_rest = instance.get('StorageEncrypted', False)
        encryption_in_transit = instance.get('PendingCloudwatchLogsExports', {}).get('LogTypesToEnable', {}).get(
            'tls', False)
        output.write(f"RDS Instance: {instance_identifier}\n")
        if not encryption_at_rest:
            count += 1
        if not encryption_in_transit:
            count += 1
        output.write(
            f"{'Data Encryption at Rest: Enabled' if encryption_at_rest else '[Vulnerability] Data Encryption at Rest: Disabled'}\n")
        output.write(
            f"{'Data Encryption in Transit: Enabled' if encryption_in_transit else '[Vulnerability] Data Encryption in Transit: Disabled'}\n")


def check_rds_security_patches(instance):
    global count
    with open(output_file, 'a') as output:
        try:
            instance_identifier = instance['DBInstanceIdentifier']
            pending_patches_count = instance.get('PendingModifiedValues', {}).get('PendingCloudWatchLogsExports',
                                                                                  {}).get('LogTypesToEnable',
                                                                                          {}).get('security', 0)
            if pending_patches_count > 0:
                output.write(
                    f"[Vulnerability] Instance has {pending_patches_count} pending security patches.\n")
                count += 1
            else:
                output.write(f"Instance is up-to-date.\n")
        except Exception as e:
            output.write(f"Error: {str(e)}\n")


def check_rds_backup_status(instance):
    global count
    with open(output_file, 'a') as output:
        try:
            instance_identifier = instance['DBInstanceIdentifier']
            automated_backups = \
                rds.describe_db_instance_automated_backups(DBInstanceIdentifier=instance_identifier)[
                    'DBInstanceAutomatedBackups']
            if automated_backups:
                output.write(f"Automated Backups are turned on\n")
            else:
                count += 1
                output.write(f"[Vulnerability] Automated backups are off\n")
        except Exception as e:
            output.write(f"Error: {str(e)}\n")


def check_rds_public_access(instance):
    global count
    with open(output_file, 'a') as output:
        instance_identifier = instance['DBInstanceIdentifier']
        is_public = is_rds_public(instance)
        if is_public:
            count += 1
            output.write(f"[Vulnerability] RDS instance is publicly accessible.\n")


def is_rds_public(instance):
    return instance.get('PubliclyAccessible', False)


def run():
    response = rds.describe_db_instances()
    with open(output_file, 'a') as output:
        output.write(f'RDS Vulnerability Check Results: \n\n')
    for instance in response['DBInstances']:
        check_rds_encryption_status(instance)
        check_rds_security_patches(instance)
        check_rds_backup_status(instance)
        check_rds_public_access(instance)
    print('RDS Checks Completed')
    with open(output_file, 'a') as output:
        output.write(f'{count} vulnerabilities found \n\n')
