from datetime import datetime
import boto3

def check_security_vulnerabilities():
    session = boto3.Session()
    ec2_client = session.client('ec2')
    response = ec2_client.describe_instances()

    checked_count = 0
    detected_count = 0
    insecure_instances = []
    instance_details = {}

    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            checked_count += 1
            instance_id = instance['InstanceId']
            instance_name = [tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name']
            instance_name = instance_name[0] if instance_name else 'N/A'
            security_groups = [group['GroupName'] for group in instance['SecurityGroups']
                               if group['GroupName'] != 'default']
            vulnerabilities = []

            # Check for open ports (example: SSH and RDP)
            for group_name in security_groups:
                security_group = ec2_client.describe_security_groups(GroupNames=[group_name])['SecurityGroups'][0]
                for permission in security_group.get('IpPermissions', []):
                    if 'FromPort' in permission and 'ToPort' in permission and 'IpProtocol' in permission:
                        if permission['FromPort'] in [22, 3389] and permission['ToPort'] in [22, 3389] and permission['IpProtocol'] == 'tcp':
                            vulnerabilities.append('Open SSH/RDP Ports')

            # Check for public IP
            public_ip = instance.get('PublicIpAddress')
            if vulnerabilities or public_ip:
                detected_count += 1
                insecure_instances.append((instance_name, vulnerabilities))

            instance_details[instance_id] = (datetime.now(), instance_name, vulnerabilities, public_ip)

    with open('instance_security_checks_aggregated.txt', 'a') as file:
        file.write("DateTime, Instance ID, Instance Name, Vulnerabilities, Public IP\n")

        for instance_id, details in instance_details.items():
            file.write(f"{details[0]}, {instance_id}, {details[1]}, {', '.join(details[2]) if details[2] else 'N/A'}, {details[3] if details[3] else 'N/A'}\n")

    with open('instance_security_summary.txt', 'w') as summary_file:
        summary_file.write(f"Total instances checked: {checked_count}\n")
        summary_file.write(f"Detected insecure instances: {detected_count}\n")
        summary_file.write("Insecure instances and vulnerabilities:\n")
        for instance, vulnerabilities in insecure_instances:
            summary_file.write(f"Instance: {instance}, Vulnerabilities: {', '.join(vulnerabilities) if vulnerabilities else 'Public IP'}\n")

if __name__ == '__main__':
    check_security_vulnerabilities()
