import boto3
import json

# Text file path
txt_file_path = 'Vulnerability_Check_Results.txt'
boto3 = boto3.session.Session(profile_name="default")

count = 0


def write_to_txt(message):
    with open(txt_file_path, 'a') as txtfile:
        txtfile.write(f"{message}\n")


def check_public_s3_buckets():
    s3 = boto3.client('s3')
    global count

    response = s3.list_buckets()
    buckets = response['Buckets']
    public_buckets = []

    for bucket in buckets:
        bucket_name = bucket['Name']

        try:
            policy_response = s3.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_response['Policy'])

            # Check if the policy allows public access
            if 'Statement' in policy:
                for statement in policy['Statement']:
                    if 'Effect' in statement and statement['Effect'] == 'Allow' and 'Principal' in statement and \
                            statement['Principal'] == '*':
                        public_buckets.append(bucket_name)
                        break
        except s3.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                # No bucket policy, continue to the next bucket
                continue
            else:
                # Other error, log and continue
                write_to_txt(f'Error checking bucket policy for {bucket_name}: {e}')

    if public_buckets:
        count += 1
        write_to_txt(f'[Vulnerability] Public S3 Buckets: {public_buckets}')
    else:
        write_to_txt("No buckets public")


def check_encryption_s3_buckets():
    s3 = boto3.client('s3')
    global count

    response = s3.list_buckets()
    buckets = response['Buckets']
    unencrypted_buckets = []

    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            encryption_response = s3.get_bucket_encryption(Bucket=bucket_name)
        except s3.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                unencrypted_buckets.append(bucket_name)

    if unencrypted_buckets:
        count += 1
        write_to_txt(f'[Vulnerability] Unencrypted S3 Buckets: {unencrypted_buckets}')
    else:
        write_to_txt('Server side encryption is enabled for all buckets')


def check_versioning_s3_buckets():
    s3 = boto3.client('s3')
    global count

    response = s3.list_buckets()
    buckets = response['Buckets']
    versioning_disabled_buckets = []

    for bucket in buckets:
        bucket_name = bucket['Name']
        versioning_response = s3.get_bucket_versioning(Bucket=bucket_name)

        if 'Status' in versioning_response and versioning_response['Status'] != 'Enabled':
            versioning_disabled_buckets.append(bucket_name)

    if versioning_disabled_buckets:
        write_to_txt(f'Versioning Disabled S3 Buckets: {versioning_disabled_buckets}')
    else:
        write_to_txt("Versioning is enabled for all buckets")


def check_logging_s3_buckets():
    s3 = boto3.client('s3')
    global count

    response = s3.list_buckets()
    buckets = response['Buckets']
    logging_disabled_buckets = []

    for bucket in buckets:
        bucket_name = bucket['Name']
        logging_response = s3.get_bucket_logging(Bucket=bucket_name)

        if 'LoggingEnabled' not in logging_response:
            logging_disabled_buckets.append(bucket_name)

    if logging_disabled_buckets:
        count += 1
        write_to_txt(f'[Vulnerability] Logging Disabled S3 Buckets: {logging_disabled_buckets}')
    else:
        write_to_txt('Logging is enabled for all buckets')


def run():
    # Create a new text file or overwrite existing
    with open(txt_file_path, 'a') as txtfile:
        txtfile.write("\nS3 Vulnerability Check Results:\n\n")

    check_public_s3_buckets()
    check_encryption_s3_buckets()
    check_versioning_s3_buckets()
    check_logging_s3_buckets()

    print(f'S3 Checks Completed')
    write_to_txt(f'{count} vulnerabilities found.\n')
