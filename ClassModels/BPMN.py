class BPMN:
    def __init__(self, BPMNJson):
        self.resource_pool_number = BPMNJson["ResourcePools"]["ResourcePoolNumbers"]
        resource_pools = []
        for i in range(self.resource_pool_number):
            one_resource = {}
            one_resource["Name"] = BPMNJson["ResourcePools"][f"ResourcePool{i + 1}"]["Name"]
            one_resource["ResourceNumber"] = BPMNJson["ResourcePools"][f"ResourcePool{i + 1}"]["ResourceNumbers"]
            resource_list = []
            for j in range(one_resource["ResourceNumber"]):
                resource_list.append(BPMNJson["ResourcePools"][f"ResourcePool{i + 1}"][f"Resource{j + 1}"]["Name"])
            one_resource["Resources"] = resource_list
            one_resource["RelatedSubnet"] = BPMNJson["ResourcePools"][f"ResourcePool{i + 1}"]["SubnetNumber"]
            one_resource["Dependencies"] = BPMNJson["ResourcePools"][f"ResourcePool{i + 1}"]["Dependencies"]
            resource_pools.append(one_resource)
        self.resource_pools = resource_pools
        self.change_dependency_to_number()

        self.process_number = BPMNJson["Processes"]["ProcessNumbers"]
        processes = []
        for i in range(self.process_number):
            one_process = {}
            one_process["Name"] = BPMNJson["Processes"][f"Process{i + 1}"]["Name"]
            one_process["RelatedResourcePool"] = BPMNJson["Processes"][f"Process{i + 1}"]["ResourcePool"]
            processes.append(one_process)
        self.processes = processes
        self.change_resource_pool_related_to_process_to_number()

        self.workflow_path_number = BPMNJson["WorkFlows"]["PathNumbers"]
        paths = []
        for i in range(self.workflow_path_number):
            return_paths = self.add_path_to_workflow(BPMNJson["WorkFlows"][f"Path{i + 1}"], [])
            paths.extend(return_paths)
        self.workflow_paths = paths
        self.find_priority_of_workflow_path(BPMNJson["WorkFlows"])

        self.mission_number = BPMNJson["Missions"]["MissionNumbers"]
        missions = []
        for i in range(self.mission_number):
            one_mission = {}
            one_mission["Name"] = BPMNJson["Missions"][f"Mission{i + 1}"]["Name"]
            one_mission["Processes"] = BPMNJson["Missions"][f"Mission{i + 1}"]["Processes"]
            one_mission["Priority"] = BPMNJson["Missions"][f"Mission{i + 1}"]["Priority"]
            missions.append(one_mission)
        self.missions = missions

    def change_dependency_to_number(self) -> None:
        for i in range(self.resource_pool_number):
            dependency = []
            for j in range(len(self.resource_pools[i]["Dependencies"])):
                for k in range(self.resource_pool_number):
                    if self.get_resource_pool_name(k + 1) == self.resource_pools[i]["Dependencies"][j]:
                        dependency.append(k + 1)
                        break
            self.resource_pools[i]["Dependencies"] = dependency

    def change_resource_pool_related_to_process_to_number(self) -> None:
        for i in range(self.process_number):
            for j in range(self.resource_pool_number):
                if self.get_resource_pool_name(j + 1) == self.processes[i]["RelatedResourcePool"]:
                    self.processes[i]["RelatedResourcePool"] = j + 1
    
    def get_resource_pool(self, number: int):
        if number > self.resource_pool_number:
            raise "number is bigger than number of resource pools"
        return self.resource_pools[number - 1]
        
    def get_resource_pool_name(self, number: int) -> str:
        if number > self.resource_pool_number:
            raise "number is bigger than number of resource pools"
        return self.resource_pools[number - 1]["Name"]

    def add_path_to_workflow(self, path, return_paths) -> list:
        ordered_keys = path["OrderedKeys"]
        for key in ordered_keys:
            if "GateWays" in key:
                if "Parallel" == path[key]["Type"]:
                    for j in range(path[key]["PathNumbers"]):
                        internal_return_path = self.add_path_to_workflow(path[key][f"Path{j + 1}"], [])
                        #return_paths.extend(internal_return_path)
                        if j == 0:
                            for k in range(len(internal_return_path)):
                                return_paths[j].extend(internal_return_path[k])
                        else:
                            return_paths.append(return_paths[0][:len(return_paths[0])-1])
                            for k in range(len(internal_return_path)):
                                return_paths[j].extend(internal_return_path[k])
            else:
                if len(return_paths) == 0:
                    return_paths.append(path[key][:])
                else:
                    for j in range(len(return_paths)):
                        return_paths[j].extend(path[key][:])
        return return_paths

    def find_priority_of_workflow_path(self, workflows_json) -> None:
        return_list = []
        for i in range(len(self.workflow_paths)):
            one_path_json = {}
            one_path = self.workflow_paths[i]
            for process_name in one_path:
                priority = self.find_priority_of_process_in_workflow(process_name, workflows_json)
                if priority is not None:
                    one_path_json["Path"] = one_path
                    one_path_json["Priority"] = priority
                    break
            return_list.append(one_path_json)
        self.workflow_paths = return_list

    def find_priority_of_process_in_workflow(self, process_name, workflows_json):
        for i in range(workflows_json["PathNumbers"]):
            ordered_keys = workflows_json[f"Path{i + 1}"]["OrderedKeys"]
            for key in ordered_keys:
                if "Processes" in key:
                    if process_name in workflows_json[f"Path{i + 1}"][key]:
                        if workflows_json[f"Path{i + 1}"]["HasPriority"]:
                            return workflows_json[f"Path{i + 1}"]["Priority"]
                        else:
                            return None
                else:
                    return self.find_priority_of_process_in_workflow(process_name, workflows_json[f"Path{i + 1}"][key])
        return None


