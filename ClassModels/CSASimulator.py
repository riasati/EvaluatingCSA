import copy
import random

from ClassModels.Attacker import Attacker
from ClassModels.NetworkState import NetworkState


class CSA:
    def __init__(self, attacker: Attacker, network_state: NetworkState, csa_correctness: float, probabilities: list, is_random_csa: bool):
        self.attacker = attacker
        self.network_state = network_state
        self.network_state_simulator = copy.deepcopy(network_state)
        self.csa_correctness = csa_correctness
        self.probabilities = probabilities
        self.is_random_csa = is_random_csa
        self.current_attack_path = []
        self.prediction_of_first_node = ""
        self.prediction_of_second_node = ""
        if len(self.probabilities) != 4:
            raise Exception("you have to provide four probabilities for creating fake change in one host.")

    def initialize_state(self, network_state: NetworkState):
        self.network_state = network_state
        self.network_state_simulator = copy.deepcopy(network_state)

    def update_current_attack_path(self):
        self.current_attack_path = self.attacker.current_current_attack_path[:]

    # def report_current_state(self, call_from_future:bool = False) -> float:
    #     if self.is_random_csa:
    #         self.csa_correctness = random.random()
    #     if random.random() > self.csa_correctness:
    #         if call_from_future:
    #             if self.attacker.current_second_node == "None" or self.attacker.current_second_node == "None:S" or self.attacker.current_second_node == "None:F":
    #                 different_host = None
    #             else:
    #                 different_host = self.network_state_simulator.find_related_host(self.attacker.get_target_address_of_attack(self.attacker.current_second_node))
    #         else:
    #             if self.attacker.current_first_node == "None" or self.attacker.current_first_node == "None:S" or self.attacker.current_first_node == "None:F":
    #                 different_host = None
    #             else:
    #                 different_host = self.network_state_simulator.find_related_host(self.attacker.get_target_address_of_attack(self.attacker.current_first_node))
    #         #different_host = self.network_state.which_host_is_different(self.network_state_simulator)
    #         if different_host is None:
    #             business_factor = self.network_state_simulator.calculate_business_factor_with_state()
    #             return business_factor
    #         self.network_state_simulator.fake_change_in_host(different_host, self.probabilities)
    #         business_factor = self.network_state_simulator.calculate_business_factor_with_state()
    #         self.network_state_simulator.hosts = copy.deepcopy(self.network_state.hosts)
    #         return business_factor
    #
    #     else:
    #         self.network_state_simulator.hosts = copy.deepcopy(self.network_state.hosts)
    #         business_factor = self.network_state_simulator.calculate_business_factor_with_state()
    #         return business_factor
    #
    # def report_project_state(self):
    #     future_real_business_factor = None
    #     current_state_in_network = copy.deepcopy(self.network_state.hosts)
    #     current_state_in_network_simulator = copy.deepcopy(self.network_state_simulator.hosts)
    #     first_node, second_node = self.attacker.get_future_nodes_in_path()
    #     if first_node != "None" and first_node != "None:S" and first_node != "None:F":
    #         self.network_state.real_change_in_network(self.attacker, first_node, second_node)
    #         future_real_business_factor = self.network_state.calculate_business_factor_with_state()
    #     business_factor = self.report_current_state(True)
    #     self.network_state.hosts = current_state_in_network
    #     self.network_state_simulator.hosts = current_state_in_network_simulator
    #     return future_real_business_factor, business_factor

    def report_current_state(self) -> float:
        if self.prediction_of_first_node != "None" and self.prediction_of_first_node != "None:S" and self.prediction_of_first_node != "None:F":
            self.network_state_simulator.hosts = self.network_state_simulator.real_change_in_network(self.attacker,
                                                                                                     self.prediction_of_first_node,
                                                                                                     self.prediction_of_second_node)
        business_factor = self.network_state_simulator.calculate_business_factor_with_state()
        return business_factor

    def report_project_state(self):
        future_real_business_factor = None
        current_state_in_network = copy.deepcopy(self.network_state.hosts)
        current_state_in_network_simulator = copy.deepcopy(self.network_state_simulator.hosts)

        first_node, second_node = self.attacker.get_future_nodes_in_path()

        if first_node != "None" and first_node != "None:S" and first_node != "None:F":
            self.network_state.real_change_in_network(self.attacker, first_node, second_node)
            future_real_business_factor = self.network_state.calculate_business_factor_with_state()

        if self.prediction_of_second_node == "None" or self.prediction_of_second_node == "None:S" or self.prediction_of_second_node == "None:F":
            return future_real_business_factor, None

        prediction_success_node = self.attacker.get_success_attack_node(self.prediction_of_second_node)
        prediction_failure_node = self.attacker.get_failure_attack_node(self.prediction_of_second_node)

        if random.random() > self.csa_correctness:
            if random.random() > 0.5:
                self.network_state_simulator.hosts = self.network_state_simulator.real_change_in_network(
                    self.attacker,
                    self.prediction_of_second_node,
                    prediction_success_node)

            else:
                self.network_state_simulator.hosts = self.network_state_simulator.real_change_in_network(
                    self.attacker,
                    self.prediction_of_second_node,
                    prediction_failure_node)

        else:
            if first_node == self.prediction_of_second_node:
                self.network_state_simulator.hosts = self.network_state_simulator.real_change_in_network(
                    self.attacker,
                    self.prediction_of_second_node,
                    second_node)
            else:
                if random.random() > 0.5:
                    self.network_state_simulator.hosts = self.network_state_simulator.real_change_in_network(
                        self.attacker,
                        self.prediction_of_second_node,
                        prediction_success_node)

                else:
                    self.network_state_simulator.hosts = self.network_state_simulator.real_change_in_network(
                        self.attacker,
                        self.prediction_of_second_node,
                        prediction_failure_node)


        csa_future_business_factor = self.network_state_simulator.calculate_business_factor_with_state()

        self.network_state.hosts = current_state_in_network
        self.network_state_simulator.hosts = current_state_in_network_simulator

        return future_real_business_factor, csa_future_business_factor

    def predication_of_near_nodes(self):
        if self.is_random_csa:
            self.csa_correctness = random.random()

        if random.random() > self.csa_correctness:
            if len(self.current_attack_path) == 0:
                self.current_attack_path.append(self.attacker.current_first_node)
                self.prediction_of_first_node = self.attacker.current_first_node

            else:
                success_node = self.attacker.get_success_attack_node(self.current_attack_path[-1])
                failure_node = self.attacker.get_failure_attack_node(self.current_attack_path[-1])
                if random.random() > self.csa_correctness:
                    if random.random() > 0.5:
                        self.prediction_of_first_node = success_node
                    else:
                        self.prediction_of_first_node = failure_node
                else:
                    self.prediction_of_first_node = self.attacker.current_first_node

        else:
            self.prediction_of_first_node = self.attacker.current_first_node
            self.current_attack_path.append(self.prediction_of_first_node)


        if random.random() > self.csa_correctness:
            success_node = self.attacker.get_success_attack_node(self.current_attack_path[-1])
            failure_node = self.attacker.get_failure_attack_node(self.current_attack_path[-1])
            if random.random() > self.csa_correctness:
                if random.random() > 0.5:
                    self.prediction_of_second_node = success_node
                else:
                    self.prediction_of_second_node = failure_node
            else:
                self.prediction_of_second_node = self.attacker.current_second_node
        else:
            self.prediction_of_second_node = self.attacker.current_second_node

