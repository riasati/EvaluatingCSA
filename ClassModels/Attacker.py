import random
import json
import ast
class Attacker:
    def __init__(self, attack_json):
        self.attack_path_list_object = None
        self.current_attack_path : list = None
        self.current_current_attack_path: list = None
        self.current_first_node: str = None
        self.current_second_node: str = None
        self.least_probability_of_all_paths: float = None
        self.appropriate_attack_path_number: int = None
        self.attack_path_graph = attack_json
        self.all_paths = None

    def get_success_attack_node(self, attack_node_name: str) -> str:
        attack_node_name = attack_node_name.split(":")[0]
        if attack_node_name not in self.attack_path_graph.keys():
            raise Exception(f"there is no node with this name {attack_node_name}")
        node_name: str = self.attack_path_graph[attack_node_name]["SuccessPath"]
        return node_name

    def get_failure_attack_node(self, attack_node_name: str) -> str:
        attack_node_name = attack_node_name.split(":")[0]
        if attack_node_name not in self.attack_path_graph.keys():
            raise Exception(f"there is no node with this name {attack_node_name}")
        node_name: str = self.attack_path_graph[attack_node_name]["FailurePath"]
        return node_name

    def get_target_address_of_attack(self, attack_node_name: str) -> str:
        attack_node_name = attack_node_name.split(":")[0]
        if attack_node_name not in self.attack_path_graph.keys():
            raise Exception(f"there is no node with this name {attack_node_name}")
        target: str = self.attack_path_graph[attack_node_name]["Target"]
        return target

    def get_attack_stage_of_attack(self, attack_node_name: str) -> list:
        attack_node_name = attack_node_name.split(":")[0]
        if attack_node_name not in self.attack_path_graph.keys():
            raise Exception(f"there is no node with this name {attack_node_name}")
        attack_stage: list = self.attack_path_graph[attack_node_name]["AttackStage"]
        return attack_stage

    def get_vulnerability_of_attack(self, attack_node_name: str) -> str:
        attack_node_name = attack_node_name.split(":")[0]
        if attack_node_name not in self.attack_path_graph.keys():
            raise Exception(f"there is no node with this name {attack_node_name}")
        vulnerability: str = self.attack_path_graph[attack_node_name]["Vulnerability"]
        return vulnerability

    def get_host_related_security_factor(self, attack_node_name: str, hosts_configuration: list) -> float:
        attack_node_name = attack_node_name.split(":")[0]
        if attack_node_name not in self.attack_path_graph.keys():
            raise Exception(f"there is no node with this name {attack_node_name}")
        attack_node = self.attack_path_graph[attack_node_name]
        desired_hosts = [x for x in hosts_configuration if x["Address"] == attack_node["Target"]]
        if len(desired_hosts) == 0:
            raise Exception("address of host does not match with attack address")
        desired_host = desired_hosts[0]
        return desired_host["SecurityFactor"]

    def is_attack_successful(self, attack_node_name: str, security_factor: float) -> bool:
        attack_node_name = attack_node_name.split(":")[0]
        if attack_node_name not in self.attack_path_graph.keys():
            raise Exception(f"there is no node with this name {attack_node_name}")
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
            raise Exception("there is no node with this name")
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

    def create_numbers_of_attack_path(self, attack_node_name: str, hosts_configuration: list):

        def convert_single_and_double_quote(one_string: str) -> str:
            return one_string.replace('"', "'")

        import json
        return_object = {}
        for i in range(self.appropriate_attack_path_number):
            one_attack_path = self.create_attack_path(attack_node_name, hosts_configuration, [])
            one_attack_path_string = json.dumps(one_attack_path)
            one_attack_path_string = convert_single_and_double_quote(one_attack_path_string)
            if one_attack_path_string not in return_object:
                return_object[one_attack_path_string] = 1
            else:
                return_object[one_attack_path_string] += 1
        self.attack_path_list_object = return_object

    # def calculate_probability_of_most_successful_path(self, hosts_configuration, first_node:str):
    #     probability: float = 1
    #     next_node = first_node
    #     while next_node != "None":
    #         security_factor: float = self.get_host_related_security_factor(next_node, hosts_configuration)
    #         probability *= self.attack_path_graph[next_node]["SuccessRate"] * (1 - security_factor)
    #         next_node = self.get_success_attack_node(next_node)
    #     self.probability_of_most_successful_path = probability
    #     return probability

    def create_all_paths(self):
        def dfs(data, path, paths):
            datum = path[-1]
            if datum in data:
                for val in [self.get_success_attack_node(datum), self.get_failure_attack_node(datum)]:
                    new_path = path + [val]
                    paths = dfs(data, new_path, paths)
            else:
                paths += [path]
            return paths

        def enumerate_paths(graph):
            nodes = list(graph.keys())
            all_paths = []
            for node in nodes:
                node_paths = dfs(graph, [node], [])
                all_paths += node_paths
            return all_paths

        self.all_paths = enumerate_paths(self.attack_path_graph)


    def calculate_probability_of_longest_path(self, hosts_configuration, first_node:str):

        first_node_paths = []
        for one_list in self.all_paths:
            if one_list[0] == first_node:
                first_node_paths.append(one_list)

        least_probability: float = 1
        for path in first_node_paths:
            probability = 1
            for i in range(len(path)):
                if i == len(path) - 1:
                    continue
                node = path[i]
                next_node = path[i + 1]
                security_factor: float = self.get_host_related_security_factor(node, hosts_configuration)
                if next_node == self.get_success_attack_node(node):
                    probability *= self.attack_path_graph[node]["SuccessRate"] * (1 - security_factor)
                else:
                    probability *= (1 - (self.attack_path_graph[node]["SuccessRate"] * (1 - security_factor)))
            if least_probability > probability:
                least_probability = probability

        self.least_probability_of_all_paths = least_probability
        return least_probability


    def calculate_appropriate_attack_path_number(self):
        appropriate_number = (1.0 / self.least_probability_of_all_paths)
        appropriate_number = int(appropriate_number)
        quotient = appropriate_number // 100
        remain = appropriate_number % 100
        if remain >= 50:
            quotient += 1
        appropriate_number = quotient * 100
        if appropriate_number > 10000:
            print(appropriate_number)
            appropriate_number = 10000
        self.appropriate_attack_path_number = appropriate_number
        return appropriate_number


    def fill_current_attack_path(self, attack_path_string):
        if self.attack_path_list_object is None:
            raise Exception("you have to call create_numbers_of_attack_path before this")
        if attack_path_string not in self.attack_path_list_object.keys():
            raise Exception("attack_path_string_error")

        self.current_attack_path = ast.literal_eval(attack_path_string)
        #self.current_attack_path = json.loads(attack_path_string)
        self.current_first_node = self.current_attack_path[0]
        self.current_second_node = self.current_attack_path[1]

    def get_future_nodes_in_path(self):
        if self.current_attack_path is None:
            raise Exception("you have to call fill_current_attack_path before this")
        if self.current_second_node is None:
            raise Exception("you have to fill second node first before this")
        if self.current_second_node == "None":
            return self.current_second_node, self.current_second_node
        if self.current_second_node == "None:S":
            return self.current_second_node, self.current_second_node
        if self.current_second_node == "None:F":
            return self.current_second_node, self.current_second_node
        return self.current_second_node, self.current_attack_path[self.current_attack_path.index(self.current_second_node) + 1]