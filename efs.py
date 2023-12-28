import boto3
from datetime import datetime


def count_inaccessible_files(efs_client, file_system_id):
    response = efs_client.describe_mount_targets(FileSystemId=file_system_id)
    inaccessible_count = 0

    for target in response['MountTargets']:
        if target['LifeCycleState'] != 'available':
            inaccessible_count += 1

    return inaccessible_count


def count_unsecured_files(efs_client, file_system_id):
    response = efs_client.describe_mount_targets(FileSystemId=file_system_id)
    unsecured_count = 0

    for target in response['MountTargets']:
        if target['LifeCycleState'] == 'available':
            if 'IpAddress' in target:
                ip_address = target['IpAddress']
                if not ip_address.startswith(('172.', '10.', '192.168.')):
                    unsecured_count += 1

    return unsecured_count


def save_to_txt(file_system_name, file_system_id, timestamp, unsecured_count, inaccessible_count):
    output_file = "efs_report.txt"

    with open(output_file, mode='a', newline='') as txt_file:
        txt_file.write(f"FileSystemName: {file_system_name}\n")
        txt_file.write(f"FileSystemId: {file_system_id}\n")
        txt_file.write(f"Timestamp: {timestamp}\n")
        txt_file.write(f"IsUnsecured: {'Yes' if unsecured_count > 0 else 'No'}\n")
        txt_file.write(f"InaccessibleCount: {'mounted' if inaccessible_count == 0 else 'not mounted'}\n")
        txt_file.write("\n")


def main():
    efs_client = boto3.client('efs')

    response = efs_client.describe_file_systems()
    file_systems = response['FileSystems']

    vulnerabilities = 0
    total_checks = 0
    total_unsecured_count = 0

    for file_system in file_systems:
        file_system_id = file_system['FileSystemId']
        file_system_name = file_system.get('Name', 'Unnamed')

        unsecured_count = count_unsecured_files(efs_client, file_system_id)
        inaccessible_count = count_inaccessible_files(efs_client, file_system_id)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_to_txt(file_system_name, file_system_id, timestamp, unsecured_count, inaccessible_count)

        # Increment checks run for EFS count only for unique conditions checked
        if unsecured_count > 0 or inaccessible_count > 0:
            total_checks += 1

        if unsecured_count > 0:
            vulnerabilities += unsecured_count

        if inaccessible_count > 0:
            vulnerabilities += inaccessible_count

    print(f"Vulnerabilities Found: {vulnerabilities}")
    print(f"Total Unsecured EFS Files Count: {total_unsecured_count}")


if __name__ == "__main__":
    main()
