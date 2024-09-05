import random
class Attacker:
    def __init__(self, attack_json):
        self.attack_path_graph = attack_json

    def get_success_attack_node(self, attack_node_name: str) -> str:
        if attack_node_name not in self.attack_path_graph.keys():
            raise "there is no node with this name"
        node_name: str = self.attack_path_graph[attack_node_name]["SuccessPath"]
        return node_name

    def get_failure_attack_node(self, attack_node_name: str) -> str:
        if attack_node_name not in self.attack_path_graph.keys():
            raise "there is no node with this name"
        node_name: str = self.attack_path_graph[attack_node_name]["FailurePath"]
        return node_name

    def get_target_address_of_attack(self, attack_node_name: str) -> str:
        if attack_node_name not in self.attack_path_graph.keys():
            raise "there is no node with this name"
        target: str = self.attack_path_graph[attack_node_name]["Target"]
        return target

    def get_attack_stage_of_attack(self, attack_node_name: str) -> list:
        if attack_node_name not in self.attack_path_graph.keys():
            raise "there is no node with this name"
        attack_stage: list = self.attack_path_graph[attack_node_name]["AttackStage"]
        return attack_stage

    def get_vulnerability_of_attack(self, attack_node_name: str) -> str:
        if attack_node_name not in self.attack_path_graph.keys():
            raise "there is no node with this name"
        vulnerability: str = self.attack_path_graph[attack_node_name]["Vulnerability"]
        return vulnerability

    def get_host_related_security_factor(self, attack_node_name: str, hosts_configuration: list) -> float:
        if attack_node_name not in self.attack_path_graph.keys():
            raise "there is no node with this name"
        attack_node = self.attack_path_graph[attack_node_name]
        desired_hosts = [x for x in hosts_configuration if x["Address"] == attack_node["Target"]]
        if len(desired_hosts) == 0:
            raise "address of host does not match with attack address"
        desired_host = desired_hosts[0]
        return desired_host["SecurityFactor"]

    def is_attack_successful(self, attack_node_name: str, security_factor: float) -> bool:
        if attack_node_name not in self.attack_path_graph.keys():
            raise "there is no node with this name"
        success_rate = self.attack_path_graph[attack_node_name]["SuccessRate"] * (1 - security_factor)
        probability = random.random()
        if probability > success_rate:
            return False
        else:
            return True

    def create_attack_path(self, attack_node_name: str, hosts_configuration: list, attack_path_names:list):
        if len(attack_path_names) == 0:
            attack_path_names.append(attack_node_name)
        if attack_node_name == 'None':
            return attack_path_names
        if attack_node_name not in self.attack_path_graph.keys():
            raise "there is no node with this name"
        security_factor: float = self.get_host_related_security_factor(attack_node_name, hosts_configuration)
        is_attack_successful = self.is_attack_successful(attack_node_name, security_factor)
        success_node = self.get_success_attack_node(attack_node_name)
        failure_node = self.get_failure_attack_node(attack_node_name)

        if success_node == failure_node:
            if is_attack_successful:
                attack_path_names.append(f"{success_node}:S")
            else:
                attack_path_names.append(f"{failure_node}:F")
        else:
            if is_attack_successful:
                attack_path_names.append(success_node)
                if success_node == 'None':
                    return attack_path_names
            else:
                attack_path_names.append(failure_node)
                if failure_node == 'None':
                    return attack_path_names

        if is_attack_successful:
            self.create_attack_path(success_node, hosts_configuration, attack_path_names)
        else:
            self.create_attack_path(failure_node, hosts_configuration, attack_path_names)
        return attack_path_names

    def create_numbers_of_attack_path(self, attack_node_name: str, hosts_configuration: list, desired_number: int):
        import json
        return_object = {}
        for i in range(desired_number):
            one_attack_path = self.create_attack_path(attack_node_name, hosts_configuration, [])
            one_attack_path_string = json.dumps(one_attack_path)
            if one_attack_path_string not in return_object:
                return_object[one_attack_path_string] = 1
            else:
                return_object[one_attack_path_string] += 1
        self.attack_path_list_object = return_object