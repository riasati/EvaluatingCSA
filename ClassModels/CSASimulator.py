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
        if len(self.probabilities) != 4:
            raise "you have to provide four probabilities for creating fake change in one host."

    def report_current_state(self) -> float:
        if self.is_random_csa:
            self.csa_correctness = random.random()
        if random.random() > self.csa_correctness:
            different_host = self.network_state.which_host_is_different(self.network_state_simulator)
            if different_host is None:
                business_factor = self.network_state_simulator.calculate_business_factor_with_state()
                return business_factor
            self.network_state_simulator.fake_change_in_host(different_host, self.probabilities)
            business_factor = self.network_state_simulator.calculate_business_factor_with_state()
            self.network_state_simulator.hosts = copy.deepcopy(self.network_state.hosts)
            return business_factor

        else:
            self.network_state_simulator.hosts = copy.deepcopy(self.network_state.hosts)
            business_factor = self.network_state_simulator.calculate_business_factor_with_state()
            return business_factor

    def report_project_state(self) -> float:
        current_state_in_network = copy.deepcopy(self.network_state.hosts)
        current_state_in_network_simulator = copy.deepcopy(self.network_state_simulator.hosts)
        first_node, second_node = self.attacker.get_future_nodes_in_path()
        if first_node != "None":
            self.network_state.real_change_in_network(self.attacker, first_node, second_node)
        business_factor = self.report_current_state()
        self.network_state.hosts = current_state_in_network
        self.network_state_simulator.hosts = current_state_in_network_simulator
        return business_factor
