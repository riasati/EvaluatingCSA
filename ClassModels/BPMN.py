from copy import deepcopy


class BPMN:
    def __init__(self, bpmn_json):
        self.business_importance = None
        self.resource_numbers = bpmn_json["Resources"]["ResourceNumbers"]
        resources = []
        for i in range(self.resource_numbers):
            one_resource = {"Name": bpmn_json["Resources"][f"Resource{i + 1}"]["Name"],
                            "HostAddresses": bpmn_json["Resources"][f"Resource{i + 1}"]["HostAddresses"],
                            "Dependencies": bpmn_json["Resources"][f"Resource{i + 1}"]["Dependencies"]}
            resources.append(one_resource)
        self.resources = resources

        self.activity_number = bpmn_json["Activities"]["ActivityNumbers"]
        activities = []
        for i in range(self.activity_number):
            one_activity = {"Name": bpmn_json["Activities"][f"Activity{i + 1}"]["Name"],
                           "RelatedResource": bpmn_json["Activities"][f"Activity{i + 1}"]["Resource"]}
            activities.append(one_activity)
        self.activities = activities

        self.workflow_numbers = bpmn_json["WorkFlows"]["WorkFlowNumbers"]
        workflows = []
        for i in range(self.workflow_numbers):
            one_workflow = {"Importance": bpmn_json["WorkFlows"][f"WorkFlow{i + 1}"]["Importance"],
                            "Name": bpmn_json["WorkFlows"][f"WorkFlow{i + 1}"]["Name"],
                            "Activities": bpmn_json["WorkFlows"][f"WorkFlow{i + 1}"]["Activities"]}
            workflows.append(one_workflow)
        self.workflows = workflows

        self.mission_number = bpmn_json["Missions"]["MissionNumbers"]
        missions = []
        for i in range(self.mission_number):
            one_mission = {"Name": bpmn_json["Missions"][f"Mission{i + 1}"]["Name"],
                           "Activities": bpmn_json["Missions"][f"Mission{i + 1}"]["Activities"],
                           "Importance": bpmn_json["Missions"][f"Mission{i + 1}"]["Importance"],
                           "Type": bpmn_json["Missions"][f"Mission{i + 1}"]["Type"],
                           "Weights": bpmn_json["Missions"][f"Mission{i + 1}"]["Weights"]
                           }
            missions.append(one_mission)
        self.missions = missions

        self.calculate_business_importance()
        self.calculate_activity_importance()

    def calculate_business_importance(self) -> None:
        importance = 0
        for workflow in self.workflows:
            importance += workflow["Importance"]
        for mission in self.missions:
            importance += mission["Importance"]
        self.business_importance = importance

    def calculate_activity_importance(self):
        for activity in self.activities:
            importance = 0.0
            activity_name = activity["Name"]
            for workflow in self.workflows:
                if activity_name in workflow["Activities"]:
                    importance += (workflow["Importance"] * 1.0) / (len(workflow["Activities"]) - 2)
            for mission in self.missions:
                if activity_name in mission["Activities"]:
                    # TODO
                    importance += (mission["Importance"] * 1.0) / len(mission["Activities"])
            activity["Importance"] = importance




