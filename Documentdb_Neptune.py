import boto3

boto3 = boto3.session.Session(profile_name="default", region_name="us-east-1")
client = boto3.client('neptune')
count = 0
txt_file_path = 'Vulnerability_Check_Results.txt'

def write_to_txt(message):
    with open(txt_file_path, 'a') as txtfile:
        txtfile.write(f"{message}")

def check_ddb_neptune_security_vulnerabilities():
    global count
    response = client.describe_db_clusters()

    with open('neptune_security_checks.txt', 'a') as txtfile:
        for cluster in response['DBClusters']:
            cluster_identifier = cluster['DBClusterIdentifier']
            write_to_txt(f"\nDBClusterIdentifier: {cluster_identifier}\n")

            # Check if encryption at rest is enabled
            storage_encrypted = cluster.get('StorageEncrypted', False)
            if not storage_encrypted:
                count += 1
            write_to_txt(
                f"{'StorageEncrypted: True\n' if storage_encrypted else '[Vulnerability] StorageEncrypted: False\n'}")

            # Check if IAM database authentication is enabled
            iam_authentication_enabled = cluster.get('IAMDatabaseAuthenticationEnabled', False)
            if not iam_authentication_enabled:
                count += 1
            write_to_txt(
                f"{'IAMDatabaseAuthenticationEnabled: True\n' if str(iam_authentication_enabled) else '[Vulnerability] IAMDatabaseAuthenticationEnabled: False\n'}")

            # Check if the cluster is publicly accessible
            publicly_accessible = cluster.get('PubliclyAccessible', False)
            if publicly_accessible:
                count += 1
            write_to_txt(
                f"{'[Vulnerability] PubliclyAccessible: True\n' if str(publicly_accessible) else 'PubliclyAccessible: False\n'}")

            # Check parameter group settings (modify this based on your requirements)
            parameter_groups = cluster.get('DBClusterParameterGroups', [])
            for parameter_group in parameter_groups:
                parameter_group_name = parameter_group.get('DBClusterParameterGroupName', '')
                ssl_enabled = 'ssl' in parameter_group_name.lower()
                if not ssl_enabled:
                    count += 1
                write_to_txt(
                    f"{'SSLEncryptionSupported: True\n' if str(ssl_enabled) else '[Vulnerability] SSLEncryptionSupported: False\n'}")

            # Check if automatic backups are enabled
            backup_retention_period = cluster.get('BackupRetentionPeriod', 0)
            write_to_txt(f"BackupRetentionPeriod: {str(backup_retention_period)}\n")

            # Check if deletion protection is enabled
            deletion_protection_enabled = cluster.get('DeletionProtection', False)
            if not deletion_protection_enabled:
                count += 1
            write_to_txt(
                f"{'DeletionProtection: True\n' if str(deletion_protection_enabled) else '[Vulnerability] DeletionProtection: False\n'}")


def run():
    write_to_txt(f'DocumentDB and Neptune Check Results:\n')
    check_ddb_neptune_security_vulnerabilities()
    write_to_txt(f'{count - 1} vulnerabilities found\n\n')
    print('DocumentDB and Neptune Checks Completed')

