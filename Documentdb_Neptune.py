import boto3
from botocore.exceptions import NoCredentialsError, ClientError

boto3 = boto3.session.Session(profile_name="default", region_name="us-east-1")


def check_documentdb_security(cluster_id, text_file):
    client = boto3.client('docdb')

    try:
        response = client.describe_db_clusters(DBClusterIdentifier=cluster_id)
        cluster = response['DBClusters'][0]

        # Store the data in a list for writing to the text file
        data = [
            f'DBInstanceIdentifier: {cluster_id}',
            f'SecurityGroup: No',
            f'PublicAccessibility: No',
            f'SSLEncryptionSupported: {"Yes" if cluster.get("StorageEncrypted", "N/A") == "True" else "No"}',
            f'IAMDatabaseAuthenticationEnabled: {"Yes" if cluster.get("IAMDatabaseAuthenticationEnabled", "N/A") == "True" else "No"}',
            f'StorageEncrypted: {"Yes" if cluster.get("StorageEncrypted", "N/A") == "True" else "No"}\n\n'
        ]

        # Write the information to the text file
        with open(text_file, mode='a') as file:
            file.write('\n'.join(data))
            file.write('\n\n')

    except ClientError as e:
        print(f"Error checking cluster {cluster_id}: {e}")


def list_documentdb_clusters(file):
    # Create a DocumentDB client
    client = boto3.client('docdb')

    try:
        # List all DocumentDB clusters in the account
        response = client.describe_db_clusters()
        clusters = response['DBClusters']

        if not clusters:
            print("No DocumentDB clusters found.")
        # else:
        #     print("List of DocumentDB clusters:")
        #     for cluster in clusters:
        #         cluster_id = cluster['DBClusterIdentifier']
        #         print(f"- {cluster_id}")
        #         check_documentdb_security(cluster_id, file)
        print(f'DocumentDB Checks Completed')

    except ClientError as e:
        print(f"Error listing DocumentDB clusters: {e}")


def run():
    text_file = 'Vulnerability_Check_Results.txt'
    with open(text_file, mode='a') as file:
        list_documentdb_clusters(text_file)
