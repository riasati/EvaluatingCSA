import Attacker
import NetworkState
class CSA:
    def __init__(self, attacker: Attacker, network_state: NetworkState):
        self.attacker = attacker
        self.network_state = network_state
        self.network_state_simulator = network_state

    def report_initial_state(self) -> None:
        # Calculate Vulnerability from initial state and result is file
        return None

    def report_current_state(self) -> None:
        # estimate current state with attacker and simulator state
        return None

    def report_project_state(self) -> None:
        # estimate project state with attacker and simulator state
        return None
