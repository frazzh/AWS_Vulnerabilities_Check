import boto3

boto3 = boto3.session.Session(profile_name="default")
redshift_client = boto3.client('redshift')
count = 0


def redshift_checks():
    global count

    with open('Vulnerability_Check_Results.txt', 'a') as text_file:
        text_file.write('Redshift Vulnerability Check Results:\n\n')

        redshift_clusters = redshift_client.describe_clusters()

        for cluster in redshift_clusters['Clusters']:
            # Check for publicly accessible clusters
            if cluster['PubliclyAccessible']:
                count += 1
            text_file.write(f'ClusterIdentifier: {cluster["ClusterIdentifier"]}\n')
            text_file.write(
                f'{"[Vulnerability] Publicly Accessible: True\n" if cluster['PubliclyAccessible'] else "Publicly Accessible: False\n"}')

            # Check for unencrypted snapshots
            snapshots = redshift_client.describe_cluster_snapshots(ClusterIdentifier=cluster['ClusterIdentifier'])
            unencrypted_snapshots = [snapshot['SnapshotIdentifier'] for snapshot in snapshots['Snapshots'] if
                                     not snapshot['Encrypted']]
            if unencrypted_snapshots:
                text_file.write(f'[Vulnerability] UnencryptedSnapshots: {", ".join(unencrypted_snapshots)}\n')
                count += 1

            # Check for encryption of data in transit
            if cluster['Encrypted'] and cluster['HsmStatus'] == 'active':
                text_file.write(f'DataInTransitEncryption: Enabled\n')
            else:
                text_file.write(f'[Vulnerability] DataInTransitEncryption: Disabled\n')
                count += 1

            # Check for the use of default master user credentials
            if cluster['MasterUsername'] == 'masteruser':
                text_file.write(f'[Vulnerability] Use of Master User Credentials: Yes\n')
                count += 1
            else:
                text_file.write(f'Use of Master User Credentials: No\n')

            # Check for unused or idle clusters
            if cluster['ClusterStatus'] == 'available' and cluster['NumberOfNodes'] == 0:
                text_file.write(f'UnusedIdleCluster: Yes\n')

            # Check for deprecated or vulnerable Redshift versions
            if cluster['ClusterVersion'] == 'your-deprecated-version':
                text_file.write(f'[Vulnerability] DeprecatedVulnerableVersion: Yes\n')
                count += 1

        # Check for publicly accessible snapshots
        response = redshift_client.describe_cluster_snapshots()
        publicly_accessible_snapshots = [snapshot for snapshot in response['Snapshots'] if
                                         snapshot['SnapshotType'] == 'manual' and snapshot[
                                             'SnapshotIdentifier'] != 'your-identifier']
        for snapshot in publicly_accessible_snapshots:
            text_file.write(
                f'SnapshotIdentifier: {snapshot["SnapshotIdentifier"]}\n[Vulnerability] PubliclyAccessible: Yes\n')
            count += 1

        text_file.write(f'{count} vulnerabilities found\n\n')
        print('Redshift Checks Completed')


def run():
    redshift_checks()
