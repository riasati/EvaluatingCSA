import copy
import random

from ClassModels.Attacker import Attacker
from ClassModels.BPMN import BPMN

class NetworkState:
    def __init__(self, network_json):
        self.subnet_numbers = network_json["SubnetsNumbers"]
        self.subnet_hosts = network_json["Subnets"]
        self.topology = network_json["Topology"]
        self.hosts_configuration = []

        for host in network_json["HostConfiguration"].keys():
            one_host = {"Address": host, "Os": network_json["HostConfiguration"][host]["Os"],
                        "Services": network_json["HostConfiguration"][host]["Services"],
                        "Processes": network_json["HostConfiguration"][host]["Processes"],
                        "SecurityFactor": network_json["HostConfiguration"][host]["SecurityFactor"],
                        "Importance": 0,
                        "InitialImportance": 0,
                        "CurrentImportance": 0,
                        "RelatedHosts": [],
                        "RelatedHostsImportance": []}
            self.hosts_configuration.append(one_host)
        self.hosts = copy.deepcopy(self.hosts_configuration)
        #self.hosts = self.hosts_configuration[:]
        for host in self.hosts:
            del host["Os"]
            del host["Services"]
            del host["Processes"]
            del host["SecurityFactor"]
        self.initial_state_network()
        self.compromised_factor = 0.3
        self.compromised_completely_factor = 0.5
        self.data_leaked_with_complete_compromise_factor = 0.8
        self.data_leaked_without_complete_compromise_factor = 0.6
        self.terminated_factor = 1

    def initial_state_network(self):
        for host in self.hosts:
            host["attemptedAttack"] = False
            host["IsCompromised"] = False
            host["IsCompromisedCompletely"] = False
            host["Termination"] = 0.0
            host["DataLeakage"] = 0.0
            host["Importance"] = host["InitialImportance"]
            host["CurrentImportance"] = host["Importance"]

    def get_host_numbers_of_subnet(self, subnet_number: int) -> int:
        return self.subnet_hosts[subnet_number - 1]

    def get_subnet_number_of_host(self, host) -> int:
        address: str = host["Address"]
        return int(address.split(",")[0].removeprefix("("))

    def find_related_host(self, target):
        host = [x for x in self.hosts if x["Address"] == target][0]
        return host

    def change_name_of_subnet(self, subnet_name: str):
        if subnet_name == "Internet":
            return 0
        if "Subnet" in subnet_name:
            return int(subnet_name.removeprefix("Subnet"))

    def access_of_one_subnet(self, subnet_number: int):

        if subnet_number > self.subnet_numbers:
            raise Exception("number is bigger than number of subnets")

        if subnet_number == 0:
            return [self.change_name_of_subnet(x) for x in self.topology["Internet"]]
        else:
            return [self.change_name_of_subnet(x) for x in self.topology[f"Subnet{subnet_number}"]]

    def access_of_one_subnet_to_another(self, subnet_number1: int, subnet_number2: int) -> bool:
        accesses = self.access_of_one_subnet(subnet_number1)
        if subnet_number2 in accesses:
            return True
        else:
            return False

    def real_change_in_network(self, attacker: Attacker, first_node: str, second_node: str):
        # is_attack_successful = None
        target = attacker.get_target_address_of_attack(first_node)
        if len(second_node.split(":")) > 1:
            if second_node.split(":")[1] == "S":
                is_attack_successful = True
            else:
                is_attack_successful = False
        else:
            if second_node == attacker.get_success_attack_node(first_node):
                is_attack_successful = True
            else:
                is_attack_successful = False

        target_host = self.find_related_host(target)

        if not is_attack_successful:
            target_host["attemptedAttack"] = True
            return self.hosts

        attack_stage = attacker.get_attack_stage_of_attack(first_node)
        vulnerability = attacker.get_vulnerability_of_attack(first_node)
        target_host["attemptedAttack"] = True
        if "Initial Compromise" in attack_stage:
            target_host["IsCompromised"] = True

        for attack in attack_stage:
            if attack.split(":")[0] == "Data Exfiltration":
                target_host["DataLeakage"] = float(attack.split(":")[1])

        for attack in attack_stage:
            if attack.split(":")[0] == "Terminate Node":
                target_host["Termination"] = float(attack.split(":")[1])

        if vulnerability == "privilege escalation":
            target_host["IsCompromisedCompletely"] = True

        return self.hosts

    def calculate_business_factor_with_state(self) -> float:

        def change_current_importance_of_related_host(one_host, importance_difference) -> None:
            if len(one_host["RelatedHosts"]) == 0: return
            for host_str, related_importance in zip(one_host["RelatedHosts"], one_host["RelatedHostsImportance"]):
                related_host = [x for x in self.hosts if x["Address"] == host_str][0]
                if related_importance > 0:
                    if importance_difference >= related_importance:
                        related_host["Importance"] -= related_importance
                        related_host["CurrentImportance"] = related_host["Importance"]
                        index = one_host["RelatedHosts"].index(host_str)
                        one_host["RelatedHostsImportance"][index] -= related_importance
                        index = related_host["RelatedHosts"].index(one_host["Address"])
                        related_host["RelatedHostsImportance"][index] -= related_importance
                    else:
                        related_host["Importance"] -= importance_difference
                        related_host["CurrentImportance"] = related_host["Importance"]
                        index = one_host["RelatedHosts"].index(host_str)
                        one_host["RelatedHostsImportance"][index] -= importance_difference
                        index = related_host["RelatedHosts"].index(one_host["Address"])
                        related_host["RelatedHostsImportance"][index] -= importance_difference

        business_factor = 0.0
        for host in self.hosts:
            if host["Termination"] != 0:
                difference = (((self.terminated_factor * host["Termination"]) + self.data_leaked_with_complete_compromise_factor) * host["Importance"])
                change_current_importance_of_related_host(host, difference)
                host["CurrentImportance"] = host["Importance"] - difference
                continue
            if host["DataLeakage"] != 0 and host["IsCompromisedCompletely"]:
                difference = (((self.data_leaked_with_complete_compromise_factor * host["DataLeakage"]) + self.data_leaked_without_complete_compromise_factor) * host["Importance"])
                change_current_importance_of_related_host(host, difference)
                host["CurrentImportance"] = host["Importance"] - difference
                continue
            if host["DataLeakage"] != 0 and host["IsCompromised"]:
                difference = (((self.data_leaked_without_complete_compromise_factor * host["DataLeakage"]) + self.compromised_completely_factor) * host["Importance"])
                change_current_importance_of_related_host(host, difference)
                host["CurrentImportance"] = host["Importance"] - difference
                continue
            if host["IsCompromisedCompletely"]:
                difference = (self.compromised_completely_factor * host["Importance"])
                change_current_importance_of_related_host(host, difference)
                host["CurrentImportance"] = host["Importance"] - difference
                continue
            if host["IsCompromised"]:
                difference = (self.compromised_factor * host["Importance"])
                change_current_importance_of_related_host(host, difference)
                host["CurrentImportance"] = host["Importance"] - difference
                continue
        for host in self.hosts:
            business_factor += host["CurrentImportance"]
        return business_factor

    def add_host_importance(self, bpmn: BPMN):

        def calculate_host_related_number(activity_resource_name, resources):
            number = 0
            related_resource = [x for x in resources if x["Name"] == activity_resource_name][0]
            related_host_addresses = related_resource["HostAddresses"]
            dependencies = related_resource["Dependencies"]
            number += len(related_host_addresses)
            for dependency in dependencies:
                number += calculate_host_related_number(dependency, resources)
            return number

        def add_importance(activity, resource_name, resources, host_numbers):
            related_resource = [x for x in resources if x["Name"] == resource_name][0]
            related_host_addresses = related_resource["HostAddresses"]
            related_dependencies = related_resource["Dependencies"]
            for address in related_host_addresses:
                related_host = [x for x in self.hosts_configuration if x["Address"] == address][0]
                related_host["Importance"] += (activity["Importance"] * 1.0) / host_numbers
            for dependency in related_dependencies:
                add_importance(activity, dependency, resources, host_numbers)

        def get_related_host(activity, resource_name, resources, return_host_addresses):
            related_resource = [x for x in resources if x["Name"] == resource_name][0]
            related_host_addresses = related_resource["HostAddresses"]
            related_dependencies = related_resource["Dependencies"]
            for address in related_host_addresses:
                related_host = [x for x in self.hosts_configuration if x["Address"] == address][0]
                return_host_addresses.append(related_host["Address"])
            for dependency in related_dependencies:
                get_related_host(activity, dependency, resources, return_host_addresses)

        for activity in bpmn.activities:
            host_numbers = calculate_host_related_number(activity["RelatedResource"], bpmn.resources)
            add_importance(activity, activity["RelatedResource"], bpmn.resources, host_numbers)

        for activity in bpmn.activities:
            activity_host_addresses = []
            get_related_host(activity, activity["RelatedResource"], bpmn.resources,
                             activity_host_addresses)
            for related_activity_str,importance in zip(activity["RelatedActivities"], activity["RelatedActivitiesImportance"]):
                related_activity = [x for x in bpmn.activities if x["Name"] == related_activity_str][0]
                related_host_addresses = []
                get_related_host(related_activity, related_activity["RelatedResource"], bpmn.resources, related_host_addresses)
                importance = importance / len(activity_host_addresses)
                importance = importance / len(related_host_addresses)
                for address in activity_host_addresses:
                    for address2 in related_host_addresses:
                        if address == address2: continue
                        host = [x for x in self.hosts_configuration if x["Address"] == address][0]
                        if address2 not in host["RelatedHosts"]:
                            host["RelatedHosts"].append(address2)
                            host["RelatedHostsImportance"].append(importance)
                        else:
                            index = host["RelatedHosts"].index(address2)
                            host["RelatedHostsImportance"][index] += importance

        for host_configuration in self.hosts_configuration:
            host = [x for x in self.hosts if x["Address"] == host_configuration["Address"]][0]
            host["Importance"] = host_configuration["Importance"]
            host["InitialImportance"] = host["Importance"]
            host["CurrentImportance"] = host["Importance"]
            host["RelatedHosts"] = host_configuration["RelatedHosts"]
            host["RelatedHostsImportance"] = host_configuration["RelatedHostsImportance"]



    def fake_change_in_host(self, one_host, probabilities: list):
        one_host['attemptedAttack'] = True
        is_attack_successful = random.random() > probabilities[0]
        if is_attack_successful:
            one_host['IsCompromised'] = True
            if random.random() > probabilities[1]:
                one_host['IsCompromisedCompletely'] = True
            if random.random() > probabilities[2]:
                one_host['DataLeakage'] = random.random()
            if random.random() > probabilities[3] and one_host['IsCompromisedCompletely']:
                one_host['Termination'] = random.random()

