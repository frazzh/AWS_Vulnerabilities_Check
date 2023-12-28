import boto3

flag = 0
count = 0


def check_vpc_vulnerabilities():
    global count
    ec2_client = boto3.client('ec2')
    vpcs_response = ec2_client.describe_vpcs()

    # Create a list to store the data for each VPC
    vpc_data_list = []

    for vpc in vpcs_response['Vpcs']:
        vpc_id = vpc['VpcId']
        vpc_data_list.append({'Warning': f'\nVPC ID: {vpc_id}'})
        flag = 0

        # Check for security groups allowing ingress from everywhere
        security_groups_response = ec2_client.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        for sg in security_groups_response['SecurityGroups']:
            for ingress_rule in sg['IpPermissions']:
                for ip_range in ingress_rule.get('IpRanges', []):
                    if ip_range['CidrIp'] == '0.0.0.0/0':
                        count += 1
                        vpc_data_list.append(
                            {'Warning': f"[Vulnerability] Security Group {sg['GroupId']} allows ingress traffic from everywhere."
                             })
                        break
                break

        # Check for unrestricted network ACLs
        nacls_response = ec2_client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        for nacl in nacls_response['NetworkAcls']:
            for entry in nacl['Entries']:
                if (entry['CidrBlock'] == '0.0.0.0/0' or entry.get('PortRange') == -1) and (
                        entry['RuleAction'] == 'allow' and entry['Egress'] == False):
                    count += 1
                    vpc_data_list.append({
                        'Warning': f"[Vulnerability] Network ACL {nacl['NetworkAclId']} has overly permissive rule."
                    })

        # Check for default route table with unrestricted route
        route_tables_response = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        for route_table in route_tables_response['RouteTables']:
            for route in route_table['Routes']:
                if route['DestinationCidrBlock'] == '0.0.0.0/0' and 'GatewayId' in route:
                    count += 1
                    vpc_data_list.append({
                        'Warning': f"[Vulnerability] Default route in Route Table {route_table['RouteTableId']} is overly permissive."
                    })

    txt_filename = "Vulnerability_Check_Results.txt"
    with open(txt_filename, mode='a', newline='') as txt_file:
        txt_file.write(f'VPC Vulnerability Check Results:\n')
        for vpc_data in vpc_data_list:
            txt_file.write(f"{vpc_data['Warning']}\n")
        txt_file.write(f'{count} vulnerabilities found\n')

    print(f"VPC Checks Completed")


def run():
    check_vpc_vulnerabilities()
