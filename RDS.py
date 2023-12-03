from datetime import datetime, timedelta, timezone
import boto3

aws_console = boto3.session.Session(profile_name="default")
rds = aws_console.client('rds')

output_file = 'Vulnerability_Check_Results.txt'

def check_rds_encryption_status():
    with open(output_file, 'a') as output:
        response = rds.describe_db_instances()
        for instance in response['DBInstances']:
            instance_identifier = instance['DBInstanceIdentifier']
            check_authorized_access_for_rds_instance(output, instance_identifier)
            encryption_at_rest = instance.get('StorageEncrypted', False)
            encryption_in_transit = instance.get('PendingCloudwatchLogsExports', {}).get('LogTypesToEnable', {}).get('tls', False)
            output.write(f"RDS Instance: {instance_identifier}\n")
            output.write(f"Data Encryption at Rest: {'Enabled' if encryption_at_rest else 'Disabled'}\n")
            output.write(f"Data Encryption in Transit: {'Enabled' if encryption_in_transit else 'Disabled'}\n")
            output.write("\n")


def check_authorized_access_for_rds_instance(output, instance_identifier):
    try:
        response = rds.describe_db_instances(DBInstanceIdentifier=instance_identifier)
        security_groups = response['DBInstances'][0]['VpcSecurityGroups']

        output.write(f"Authorized IP Addresses for RDS Instance '{instance_identifier}':\n")
        for security_group in security_groups:
            for ip_range in security_group['IpRanges']:
                output.write(f"  - {ip_range['CidrIp']}\n")
    except Exception as e:
        output.write(f"Error: {str(e)}\n")


def check_rds_security_patches():
    with open(output_file, 'a') as output:
        try:
            response = rds.describe_db_instances()
            output.write("RDS Instances with Pending Security Patches:\n")
            for instance in response['DBInstances']:
                instance_identifier = instance['DBInstanceIdentifier']
                pending_patches_count = instance.get('PendingModifiedValues', {}).get('PendingCloudWatchLogsExports', {}).get('LogTypesToEnable', {}).get('security', 0)
                if pending_patches_count > 0:
                    output.write(f"Instance '{instance_identifier}' has {pending_patches_count} pending security patches.\n")
                else:
                    output.write(f"Instance '{instance_identifier}' is up-to-date.\n")

        except Exception as e:
            output.write(f"Error: {str(e)}\n")


def check_rds_backup_status():
    with open(output_file, 'a') as output:
        try:
            response = rds.describe_db_instances()
            output.write("Backup Status for RDS Instances:\n")
            for instance in response['DBInstances']:
                instance_identifier = instance['DBInstanceIdentifier']
                automated_backups = rds.describe_db_instance_automated_backups(DBInstanceIdentifier=instance_identifier)['DBInstanceAutomatedBackups']
                output.write(f"\nInstance: {instance_identifier}\n")
                if automated_backups:
                    output.write("Automated Backups:\n")
                    for backup in automated_backups:
                        output.write(f" - Backup ID: {backup['DBInstanceAutomatedBackupId']}\n")
                        output.write(f" Status: {backup['Status']}\n")
                        output.write(f" Backup Creation Time: {backup['BackupRetentionPeriod']} days ago\n")
                else:
                    output.write("No automated backups found.\n")

                manual_backups = rds.describe_db_snapshots(DBInstanceIdentifier=instance_identifier)['DBSnapshots']
                if manual_backups:
                    output.write("\nManual Backups:\n")
                    for backup in manual_backups:
                        output.write(f" - Backup ID: {backup['DBSnapshotIdentifier']}\n")
                        output.write(f" Status: {backup['Status']}\n")
                        output.write(f" Backup Creation Time: {backup['SnapshotCreateTime']}\n")
                else:
                    output.write("No manual backups found.\n")

        except Exception as e:
            output.write(f"Error: {str(e)}\n")


def check_rds_public_access():
    with open(output_file, 'a') as output:
        instances = rds.describe_db_instances()['DBInstances']
        for instance in instances:
            instance_identifier = instance['DBInstanceIdentifier']
            is_public = is_rds_public(instance)
            if is_public:
                output.write(f"RDS instance {instance_identifier} is publicly accessible.\n")


def is_rds_public(instance):
    return instance.get('PubliclyAccessible', False)


def run():
    check_rds_encryption_status()
    check_rds_security_patches()
    check_rds_backup_status()
    check_rds_public_access()


if __name__ == "__main__":
    run()
