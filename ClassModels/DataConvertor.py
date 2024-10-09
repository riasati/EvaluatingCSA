import os
import csv

from ClassModels.Attacker import Attacker
from ClassModels.BPMN import BPMN
from ClassModels.NetworkState import NetworkState


class DataConvertor:
    def __init__(self):
        pass

    @staticmethod
    def convert_list_to_string(one_list):
        return " ".join(one_list)

    @staticmethod
    def create_model_csv(bpmn: BPMN, network: NetworkState, attacker: Attacker, model_path:str):
        resource_pool_path = os.path.join(model_path, 'ResourcePools.csv')
        attacker_path = os.path.join(model_path, 'Attacker.csv')
        host_path = os.path.join(model_path, 'Hosts.csv')
        mission_path = os.path.join(model_path, 'Mission.csv')
        processes_path = os.path.join(model_path, 'Processes.csv')
        subnets_path = os.path.join(model_path, 'Subnets.csv')
        workflow_path = os.path.join(model_path, 'Workflows.csv')

        resource_pool_key = ["Name", "ResourceNumber", "Resources", "Dependencies", "SubnetNumber"]
        resource_pool_value = []
        for row in bpmn.resource_pools:
            new_field = [row["Name"], row["ResourceNumber"], DataConvertor.convert_list_to_string(row["Resources"]),
                         DataConvertor.convert_list_to_string(row["Dependencies"]), row["RelatedSubnet"]]
            resource_pool_value.append(new_field)

        with open(resource_pool_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(resource_pool_key)
            csvwriter.writerows(resource_pool_value)

        process_key = ["Name", "ResourcePool"]
        process_value = []
        for row in bpmn.processes:
            new_field = [row["Name"], row["RelatedResourcePool"]]
            process_value.append(new_field)

        with open(processes_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(process_key)
            csvwriter.writerows(process_value)

        workflow_key = ["Path", "Priority"]
        workflow_value = []
        for row in bpmn.workflow_paths:
            new_field = [DataConvertor.convert_list_to_string(row["Path"]), row["Priority"]]
            workflow_value.append(new_field)

        with open(workflow_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(workflow_key)
            csvwriter.writerows(workflow_value)

        mission_key = ["Name", "Processes", "Priority"]
        mission_value = []
        for row in bpmn.missions:
            new_field = [row["Name"], DataConvertor.convert_list_to_string(row["Processes"]), row["Priority"]]
            mission_value.append(new_field)

        with open(mission_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(mission_key)
            csvwriter.writerows(mission_value)


        subnet_key = ["Name", "HostNumbers", "Relations"]
        subnet_value = [["Internet", "0"]]
        subnet_value[0].append(DataConvertor.convert_list_to_string(network.topology["Internet"]))
        for i in range(len(network.subnet_hosts)):
            new_field = [f"Subnet{i + 1}", str(network.subnet_hosts[i]), DataConvertor.convert_list_to_string(network.topology["Subnet" + str(i + 1)])]
            subnet_value.append(new_field)

        with open(subnets_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(subnet_key)
            csvwriter.writerows(subnet_value)




