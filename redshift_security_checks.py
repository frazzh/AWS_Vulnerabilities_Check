import boto3

boto3 = boto3.session.Session(profile_name="default", region_name="us-east-1")
redshift_client = boto3.client('redshift')


def redshift_checks():
    redshift_clusters = redshift_client.describe_clusters()
    vulnerability_results = []

    for cluster in redshift_clusters['Clusters']:
        result = {
            'ClusterIdentifier': cluster['ClusterIdentifier'],
            'PubliclyAccessible': cluster['PubliclyAccessible'],
            'IAMRoleAssociation': 'Yes' if 'IamRoles' in cluster and len(cluster['IamRoles']) > 0 else 'No'
        }

        # Check for unencrypted snapshots
        snapshots = redshift_client.describe_cluster_snapshots(ClusterIdentifier=cluster['ClusterIdentifier'])
        unencrypted_snapshots = [snapshot['SnapshotIdentifier'] for snapshot in snapshots['Snapshots'] if
                                 not snapshot['Encrypted']]
        result['UnencryptedSnapshots'] = ', '.join(unencrypted_snapshots) if unencrypted_snapshots else 'None'

        # Check for encryption of data in transit
        if cluster['Encrypted'] and cluster['HsmStatus'] == 'active':
            result['DataInTransitEncryption'] = 'Enabled'
        else:
            result['DataInTransitEncryption'] = 'Disabled'

        # Check for the use of default master user credentials
        result['DefaultMasterUser'] = 'Yes' if cluster['MasterUsername'] == 'masteruser' else 'No'

        vulnerability_results.append(result)

    # Check for unused or idle clusters
    unused_idle_clusters = [cluster for cluster in redshift_clusters['Clusters'] if
                            cluster['ClusterStatus'] == 'available' and cluster['NumberOfNodes'] == 0]
    unused_idle_cluster_results = [{'ClusterIdentifier': cluster['ClusterIdentifier']} for cluster in
                                   unused_idle_clusters]

    # Check for publicly accessible snapshots
    response = redshift_client.describe_cluster_snapshots()
    publicly_accessible_snapshots = [snapshot for snapshot in response['Snapshots'] if
                                     snapshot['SnapshotType'] == 'manual' and snapshot[
                                         'SnapshotIdentifier'] != 'your-identifier']
    publicly_accessible_snapshot_results = [{'SnapshotIdentifier': snapshot['SnapshotIdentifier']} for snapshot in
                                            publicly_accessible_snapshots]

    # Check for deprecated or vulnerable Redshift versions
    deprecated_vulnerable_clusters = [cluster for cluster in redshift_clusters['Clusters'] if
                                      cluster['ClusterVersion'] == 'your-deprecated-version']
    deprecated_vulnerable_cluster_results = [{'ClusterIdentifier': cluster['ClusterIdentifier']} for cluster in
                                             deprecated_vulnerable_clusters]

    # Save all results to a single text file
    with open('Vulnerability_Check_Results.txt', 'a') as text_file:
        for result in vulnerability_results:
            for key, value in result.items():
                text_file.write(f'{key}: {value}\n')

        for result in unused_idle_cluster_results:
            for key, value in result.items():
                text_file.write(f'{key}: {value}\n')

        for result in publicly_accessible_snapshot_results:
            for key, value in result.items():
                text_file.write(f'{key}: {value}\n')

        for result in deprecated_vulnerable_cluster_results:
            for key, value in result.items():
                text_file.write(f'{key}: {value}\n')

    print(f'Redshift Checks Completed')


def run():
    redshift_checks()
