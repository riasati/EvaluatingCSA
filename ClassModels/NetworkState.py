class NetworkState:
    def __init__(self, NetworkJson):
        self.subnet_numbers = NetworkJson["SubnetsNumbers"]
        self.subnet_hosts = NetworkJson["Subnets"]
        self.topology = NetworkJson["Topology"]
        self.hosts = []

        for host in NetworkJson["HostConfiguration"].keys():
            one_host = {}
            one_host["Address"] = host
            one_host["Os"] = NetworkJson["HostConfiguration"][host]["Os"]
            one_host["Services"] = NetworkJson["HostConfiguration"][host]["Services"]
            one_host["Processes"] = NetworkJson["HostConfiguration"][host]["Processes"]
            one_host["SecurityFactor"] = NetworkJson["HostConfiguration"][host]["SecurityFactor"]
            self.hosts.append(one_host)

    def initial_state_network(self):
        for host in self.hosts:
            host["attemptedAttack"] = False
            host["IsCompromised"] = False
            host["IsCompromisedCompletely"] = False
            host["IsTerminated"] = False
            host["CanWorkProperly"] = True
            host["isDataLeaked"] = False

    def get_host_numbers_of_subnet(self, subnet_number: int) -> int:
        return self.subnet_hosts(subnet_number + 1)

    def change_name_of_subnet(self, subnet_name: str):
        if subnet_name == "Internet":
            return 0
        if "Subnet" in subnet_name:
            return int(subnet_name.removeprefix("Subnet"))

    def access_of_one_subnet(self, subnet_number: int):

        if subnet_number > self.subnet_numbers:
            raise "number is bigger than number of subnets"

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
