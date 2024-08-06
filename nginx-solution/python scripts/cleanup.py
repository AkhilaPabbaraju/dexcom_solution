from google.cloud import compute_v1
from var import project_id, region, vpc_name, subnet_name, subnet_range, firewall_name, vm_name
import os
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'compute_engine_key.json'

# Initialize clients
vpc_client = compute_v1.NetworksClient()
subnet_client = compute_v1.SubnetworksClient()
firewall_client = compute_v1.FirewallsClient()
instance_client = compute_v1.InstancesClient()
operation_client = compute_v1.GlobalOperationsClient()
zone_operations_client = compute_v1.ZoneOperationsClient()

#Retrieves the zone of a given VM instance in Google Cloud.
def get_instance_zone(project_id, vm_name):

    # List all zones to search for the VM instance
    zones_client = compute_v1.ZonesClient()
    zones = zones_client.list(project=project_id)
    
    # Search for the VM instance in each zone
    for zone in zones:
        try:
            instance = instance_client.get(project=project_id, zone=zone.name, instance=vm_name)
            return zone.name
        except Exception as e:
            continue

# Cleanup function
def delete_vm(zone):
       
    # Delete the VM instance
    print('Deleting VM instance...')
    operation = instance_client.delete(project=project_id, zone=zone, instance=vm_name)
    try:
        zone_operations_client.wait(project=project_id, zone=zone, operation=operation.name)
    except Exception as e:
        print(f'Error during VM deletion wait: {e}')    
    print('VM instance deleted successfully.')

def delete_firewall():    
    # Delete the firewall rule
    print('Deleting firewall rule...')
    operation = firewall_client.delete(project=project_id, firewall=firewall_name)
    try:
        operation_client.wait(project=project_id, operation=operation.name)
    except Exception as e:
        print(f'Error during firewall rule deletion wait: {e}')    
    print('Firewall deleted successfully.')

def delete_subnet():    
    # Delete the subnet
    print('Deleting subnet...')
    operation = subnet_client.delete(project=project_id, region=region, subnetwork=subnet_name)
    print('Subnet deleted successfully.')

def delete_vpc():
    # Delete the VPC
    print('Deleting VPC...')
    operation = vpc_client.delete(project=project_id, network=vpc_name)
    try:
        operation_client.wait(project=project_id, operation=operation.name)
    except Exception as e:
        print(f'Error during VPC deletion wait: {e}')    
    
    print('VPC deleted successfully.')


def cleanup():
    # Check if VM instance already exists
    zone = get_instance_zone(project_id, vm_name)    
    if zone:
        print(f"Instance '{vm_name}' is in zone '{zone}'.")
        instances = instance_client.list(project=project_id, zone=zone)
        for instance in instances:
            if instance.name == vm_name:
                print('VM instance already exists.')
                delete_vm(zone)
                break

   # Check if firewall rule already exists
    firewalls = firewall_client.list(project=project_id)
    for firewall in firewalls:
        if firewall.name == firewall_name:        
            print('Firewall already exists.')
            delete_firewall()
            break        

   # Check if subnet already exists
    subnets = subnet_client.list(project=project_id, region=region)
    for subnet in subnets:
        if subnet.name == subnet_name:
            print('Subnet already exists.')
            delete_subnet()
            break

   # Check if VPC already exists
    vpcs = vpc_client.list(project=project_id)
    for vpc in vpcs:
        if vpc.name == vpc_name:        
            print('VPC already exists.')
            delete_vpc()
            break    

    
