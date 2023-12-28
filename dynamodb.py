import boto3
import re

count = 0

session = boto3.session.Session(profile_name="default")


def get_aws_region():
    region = session.region_name
    return region


def check_dynamodb_security(table_name, region, file_writer):
    global count
    # Create a DynamoDB client
    dynamodb = session.client('dynamodb', region_name=region)
    file_writer.write(f'DynamoDB Vulnerability Check Results:\n\n')
    # Check table existence
    try:
        file_writer.write(f'Table Name: {table_name}\n')
        table_description = dynamodb.describe_table(TableName=table_name)
    except dynamodb.exceptions.ResourceNotFoundException:
        print(f"Table '{table_name}' not found.")
        return

    encryption_at_rest = "Not enabled"
    if 'SSEDescription' in table_description['Table']:
        encryption_at_rest = table_description['Table']['SSEDescription']['Status']

    # Write Encryption at rest information to text file
    if not encryption_at_rest:
        count += 1
    file_writer.write(
        f"{'Encryption at rest: Enabled\n' if encryption_at_rest else '[Vulnerability] Encryption at rest: Disabled\n'}")

    # Extract IAM role name from table ARN
    role_name = None
    for key, value in table_description['Table'].items():
        if isinstance(value, str) and 'role' in value:
            match = re.search(r'role/([^/]+)', value)
            if match:
                role_name = match.group(1)
                break

    # Write IAM role name information to text file
    file_writer.write(
        f"{role_name or 'Unable to extract IAM role name'}\n")

    # Check if Point-in-time Recovery (PITR) is enabled
    pitr_status = table_description['Table'].get('PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus',
                                                                                           'Not enabled')

    # Write PITR status information to text file
    if not pitr_status:
        count += 1
    file_writer.write(
        f"{'Point-in-time Recovery: Enabled\n' if pitr_status else '[Vulnerability] Point-in-time Recovery: Disabled\n'}")


    # Check if Time To Live (TTL) is enabled
    ttl_status = table_description['Table'].get('TimeToLiveDescription', {}).get('TimeToLiveStatus', 'Not enabled')

    # Write TTL status information to text file
    if not ttl_status:
        count += 1
    file_writer.write(
        f"{'Time To Live (TTL): Enabled\n' if ttl_status else '[Vulnerability] Time To Live (TTL): Disabled\n'}")



    # Check if the table has global secondary indexes
    gsi_present = 'No'
    if 'GlobalSecondaryIndexes' in table_description['Table']:
        gsi_present = 'Yes'

    # Write GSI presence information to text file
    if not gsi_present:
        count += 1
    file_writer.write(
        f"{'Global Secondary Indexes (GSIs) present: True\n' if gsi_present else '[Vulnerability] Global Secondary Indexes (GSIs) present: False\n'}")

    file_writer.write(f'{count} vulnerabilities found\n\n')


def check_all_dynamodb_tables(region, file_path):
    # Create a DynamoDB client
    dynamodb = session.client('dynamodb', region_name=region)

    # Get all table names
    table_names = dynamodb.list_tables()['TableNames']

    # Open the text file for writing
    with open(file_path, mode='a') as text_file:
        # Check security for each table
        for table_name in table_names:
            check_dynamodb_security(table_name, region, text_file)


def run():
    global count
    # Dynamically retrieve the AWS region
    aws_region = get_aws_region()

    # Define the path for the text file
    text_file_path = 'Vulnerability_Check_Results.txt'

    # Check security for all DynamoDB tables and save the output to text file
    check_all_dynamodb_tables(aws_region, text_file_path)
    print(f"DynamoDB Checks Completed")
