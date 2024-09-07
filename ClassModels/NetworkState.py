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
                        "SecurityFactor": network_json["HostConfiguration"][host]["SecurityFactor"]}
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
            host["IsTerminated"] = False
            host["isDataLeaked"] = False

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

        if "Data Exfiltration" in attack_stage:
            target_host["isDataLeaked"] = True

        if "Terminate Node" in attack_stage:
            target_host["IsTerminated"] = True

        if vulnerability == "privilege escalation":
            target_host["IsCompromisedCompletely"] = True

        return self.hosts

    def calculate_business_factor_with_state(self) -> float:
        business_factor = 0.0
        for host in self.hosts:
            host_factor = host["Importance"]
            if host["IsTerminated"]:
                business_factor += host_factor - (self.terminated_factor * host_factor)
                continue
            if host["isDataLeaked"] and host["IsCompromisedCompletely"]:
                business_factor += host_factor - (self.data_leaked_with_complete_compromise_factor * host_factor)
                continue
            if host["isDataLeaked"] and host["IsCompromised"]:
                business_factor += host_factor - (self.data_leaked_without_complete_compromise_factor * host_factor)
                continue
            if host["IsCompromisedCompletely"]:
                business_factor += host_factor - (self.compromised_completely_factor * host_factor)
                continue
            if host["IsCompromised"]:
                business_factor += host_factor - (self.compromised_factor * host_factor)
                continue
            business_factor += host_factor
        return business_factor

    def add_host_importance(self, bpmn: BPMN):
        subnet_data = []
        for i in range(self.subnet_numbers):
            one_subnet = {"Number": i + 1, "Importance": 0.0}
            subnet_data.append(one_subnet)
        for process in bpmn.processes:
            desired_resource_pools = [x for x in bpmn.resource_pools if x["Name"] == process["RelatedResourcePool"]]
            if len(desired_resource_pools) == 0:
                raise Exception("related resource pool of process does not match with resource pool number")
            process_subnet_related = desired_resource_pools[0]["RelatedSubnet"]
            process_importance = process["Importance"]
            subnet = [x for x in subnet_data if x["Number"] == process_subnet_related][0]
            if len(desired_resource_pools[0]["Dependencies"]) > 0:
                dependency_number = len(desired_resource_pools[0]["Dependencies"])
                for i in range(dependency_number):
                    desired_resource_pools2 = [x for x in bpmn.resource_pools if
                                              x["Name"] == desired_resource_pools[0]["Dependencies"][i]]
                    process_subnet_related2 = desired_resource_pools2[0]["RelatedSubnet"]
                    subnet2 = [x for x in subnet_data if x["Number"] == process_subnet_related2][0]
                    subnet2["Importance"] += process_importance / (dependency_number + 1)
                subnet["Importance"] += process_importance / (dependency_number + 1)
            else:
                subnet["Importance"] += process_importance


        for host in self.hosts_configuration:
            subnet_related = self.get_subnet_number_of_host(host)
            host_number_of_subnet = self.get_host_numbers_of_subnet(subnet_related)
            subnet = [x for x in subnet_data if x["Number"] == subnet_related][0]
            host["Importance"] = (subnet["Importance"] * 1.0) / host_number_of_subnet
            host2 = [x for x in self.hosts if x["Address"] == host["Address"]][0]
            host2["Importance"] = host["Importance"]

    def which_host_is_different(self, network_state):
        for host in self.hosts:
            address = host["Address"]
            host_in_other = [x for x in network_state.hosts if x["Address"] == address][0]
            if host["attemptedAttack"] == host_in_other["attemptedAttack"] and host["IsCompromised"] == host_in_other[
                "IsCompromised"] and host["IsCompromisedCompletely"] == host_in_other["IsCompromisedCompletely"] and \
                    host["IsTerminated"] == host_in_other["IsTerminated"] and host["isDataLeaked"] == host_in_other[
                "isDataLeaked"]: continue
            return host_in_other

    def fake_change_in_host(self, one_host, probabilities: list):
        one_host['attemptedAttack'] = True
        is_attack_successful = random.random() > probabilities[0]
        if is_attack_successful:
            one_host['IsCompromised'] = True
            if random.random() > probabilities[1]:
                one_host['IsCompromisedCompletely'] = True
            if random.random() > probabilities[2]:
                one_host['isDataLeaked'] = True
            if random.random() > probabilities[3] and one_host['IsCompromisedCompletely']:
                one_host['IsTerminated'] = True

