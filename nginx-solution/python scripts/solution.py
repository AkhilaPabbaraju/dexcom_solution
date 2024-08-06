from google.cloud import compute_v1
from var import project_id, region, vpc_name, subnet_name, subnet_range, firewall_name 
from cleanup import *
import os
import time
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'compute_engine_key.json'

def createVpc():
    vpc = compute_v1.Network()
    vpc.auto_create_subnetworks = False
    vpc.name = vpc_name
    operation = vpc_client.insert(project=project_id, network_resource=vpc)

    # Wait for the VPC creation operation to complete
    try:
        operation_client.wait(project=project_id, operation=operation.name)
    except Exception as e:
        print(f'Error during VPC creation wait: {e}')
        
def createSubnet():
    subnet = compute_v1.Subnetwork()
    subnet.name = subnet_name
    subnet.network = f'projects/{project_id}/global/networks/{vpc_name}'
    subnet.ip_cidr_range = subnet_range
    subnet.region = f'regions/{region}'
    operation = subnet_client.insert(project=project_id, region=region, subnetwork_resource=subnet)
    time.sleep(30)

def createFirewall():
    firewall = compute_v1.Firewall()
    firewall.name = firewall_name
    firewall.network = f'projects/{project_id}/global/networks/{vpc_name}'
    firewall.allowed = [compute_v1.Allowed(I_p_protocol='tcp', ports=['80', '443'])]
    firewall.source_ranges = ['0.0.0.0/0']
    firewall.direction = "INGRESS"
    operation = firewall_client.insert(project=project_id, firewall_resource=firewall)

    # Wait for the Firewall rule creation operation to complete
    try:
        operation_client.wait(project=project_id, operation=operation.name)
    except Exception as e:
        print(f'Error during firewall creation wait: {e}')
        
def main():

    cleanup()
    
    # Initialize clients
    vpc_client = compute_v1.NetworksClient()
    subnet_client = compute_v1.SubnetworksClient()
    firewall_client = compute_v1.FirewallsClient()
    operation_client = compute_v1.GlobalOperationsClient()
    
    # Create VPC
    print("Creating VPC...")    
    createVpc()
    print('VPC created successfully.')
  
    # Create Subnet
    print('Creating Subnet...')
    createSubnet()
    print('Subnet created successfully')
    
    # Create Firewall rule
    print("Creating Firewall Rule...")
    createFirewall()
    print('Firewall created successfully')
    
if __name__ == "__main__":
    main()
