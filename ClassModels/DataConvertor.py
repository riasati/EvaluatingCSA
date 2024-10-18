import os
import csv
import graphviz

from ClassModels.Attacker import Attacker
from ClassModels.BPMN import BPMN
from ClassModels.MongoHelper import MongoHelper
from ClassModels.NetworkState import NetworkState


class DataConvertor:
    def __init__(self):
        pass

    @staticmethod
    def convert_list_to_string(one_list):
        for i in range(len(one_list)):
            one_list[i] = str(one_list[i])
        return " ".join(one_list)

    @staticmethod
    def create_model_csv(bpmn: BPMN, network: NetworkState, attacker: Attacker, model_path: str):

        if not os.path.exists(os.path.join(model_path, 'csv')):
            os.mkdir(os.path.join(model_path, 'csv'))

        resource_path = os.path.join(model_path, 'csv', 'Resources.csv')
        attacker_path = os.path.join(model_path, 'csv', 'Attack.csv')
        host_path = os.path.join(model_path, 'csv', 'Hosts.csv')
        mission_path = os.path.join(model_path, 'csv', 'Mission.csv')
        activity_path = os.path.join(model_path, 'csv', 'Activities.csv')
        subnets_path = os.path.join(model_path, 'csv', 'Subnets.csv')
        workflow_path = os.path.join(model_path, 'csv', 'Workflows.csv')

        resource_key = ["Name", "Dependencies", "HostAddresses"]
        resource_value = []
        for row in bpmn.resources:
            new_field = [row["Name"], DataConvertor.convert_list_to_string(row["Dependencies"]),
                         DataConvertor.convert_list_to_string(row["HostAddresses"]).replace(',', ";")]
            resource_value.append(new_field)

        with open(resource_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(resource_key)
            csvwriter.writerows(resource_value)

        activity_key = ["Name", "Resource"]
        activity_value = []
        for row in bpmn.activities:
            new_field = [row["Name"], row["RelatedResource"]]
            activity_value.append(new_field)

        with open(activity_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(activity_key)
            csvwriter.writerows(activity_value)

        workflow_key = ["Name", "Importance", "Activities"]
        workflow_value = []
        for row in bpmn.workflows:
            new_field = [row["Name"], row["Importance"], DataConvertor.convert_list_to_string(row["Activities"])]
            workflow_value.append(new_field)

        with open(workflow_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(workflow_key)
            csvwriter.writerows(workflow_value)

        mission_key = ["Name", "Activities", "Importance", "Type", "Weights"]
        mission_value = []
        for row in bpmn.missions:
            new_field = [row["Name"], DataConvertor.convert_list_to_string(row["Activities"]), row["Importance"],
                         row["Type"], DataConvertor.convert_list_to_string(row["Weights"])]
            mission_value.append(new_field)

        with open(mission_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(mission_key)
            csvwriter.writerows(mission_value)

        subnet_key = ["Name", "HostNumbers", "Relations"]
        subnet_value = [["Internet", "0"]]
        subnet_value[0].append(DataConvertor.convert_list_to_string(network.topology["Internet"]))
        for i in range(len(network.subnet_hosts)):
            new_field = [f"Subnet{i + 1}", str(network.subnet_hosts[i]),
                         DataConvertor.convert_list_to_string(network.topology["Subnet" + str(i + 1)])]
            subnet_value.append(new_field)

        with open(subnets_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(subnet_key)
            csvwriter.writerows(subnet_value)

        host_key = ["Address", "OS", "Services", "Processes", "SecurityFactor"]
        host_value = []
        for i in range(len(network.hosts_configuration)):
            new_field = [network.hosts_configuration[i]["Address"].replace(",", " "),
                         network.hosts_configuration[i]["Os"],
                         DataConvertor.convert_list_to_string(network.hosts_configuration[i]["Services"]),
                         DataConvertor.convert_list_to_string(network.hosts_configuration[i]["Processes"]),
                         network.hosts_configuration[i]["SecurityFactor"]]
            host_value.append(new_field)

        with open(host_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(host_key)
            csvwriter.writerows(host_value)

        attacker_key = ["NodeName", "ExploitName", "Vulnerability", "OS", "Service", "Process", "SuccessRate", "Target",
                        "AttackStage", "SuccessPath", "FailurePath"]
        attacker_value = []
        for key in attacker.attack_path_graph.keys():
            new_field = [key, attacker.attack_path_graph[key]["ExploitName"],
                         attacker.attack_path_graph[key]["Vulnerability"],
                         attacker.attack_path_graph[key]["Os"], attacker.attack_path_graph[key]["Service"],
                         attacker.attack_path_graph[key]["Process"], attacker.attack_path_graph[key]["SuccessRate"],
                         attacker.attack_path_graph[key]["Target"].replace(",", " "),
                         DataConvertor.convert_list_to_string(attacker.attack_path_graph[key]["AttackStage"]),
                         attacker.attack_path_graph[key]["SuccessPath"], attacker.attack_path_graph[key]["FailurePath"]]
            attacker_value.append(new_field)

        with open(attacker_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(attacker_key)
            csvwriter.writerows(attacker_value)

    @staticmethod
    def create_result_csv(model_path: str, model_number: int, mongo_helper: MongoHelper):
        result_path = os.path.join(model_path, 'csv', 'Result.csv')

        mongo_helper.add_model_number(model_number)

        records = mongo_helper.find_all_record_of_model()
        one_record = records[0]

        result_key = ["AttackPath", "AttackPathNumber", "FirstNode", "SecondNode", "RealBusinessFactor",
                      "FutureRealBusinessFactor"]

        for i in range(len(one_record["State"])):
            host_keys = one_record["State"][i].keys()
            host_keys = list(host_keys)
            if "attemptedAttack" in host_keys: host_keys.remove("attemptedAttack")
            if "Importance" in host_keys: host_keys.remove("Importance")
            for key in host_keys:
                result_key.append(f"Host{i + 1}{key}")

        result_value = []

        for record in records:
            result_field = [record["AttackPath"].replace(",", ""), record["AttackPathNumber"], record["FirstNode"],
                            record["SecondNode"], record["RealBusinessFactor"], record["FutureRealBusinessFactor"]]

            for i in range(len(record["State"])):
                host_keys = one_record["State"][i].keys()
                host_keys = list(host_keys)
                if "attemptedAttack" in host_keys: host_keys.remove("attemptedAttack")
                if "Importance" in host_keys: host_keys.remove("Importance")
                for key in host_keys:
                    if type(record["State"][i][key]) == str:
                        result_field.append(record["State"][i][key].replace(",", " "))
                    else:
                        result_field.append(record["State"][i][key])

            result_value.append(result_field)

        with open(result_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(result_key)
            csvwriter.writerows(result_value)

    @staticmethod
    def create_graph(model_path: str, model_number: int, bpmn: BPMN, network: NetworkState, attacker: Attacker):

        if not os.path.exists(os.path.join(model_path, 'graph')):
            os.mkdir(os.path.join(model_path, 'graph'))

        model_path = os.path.join(model_path, "graph")

        dot = graphviz.Digraph('AttackPathModel', comment='Attack Path', filename="AttackPath.gv",
                               graph_attr={"label": f"Attack Path of Model{model_number}", "labelloc": "t"})
        dot.format = "png"

        for key in attacker.attack_path_graph.keys():
            node_label = (
                fr"{key}\n{attacker.attack_path_graph[key]['ExploitName']}\n{attacker.attack_path_graph[key]['Vulnerability']}"
                fr"\n{attacker.attack_path_graph[key]['Target']}\n{''.join(attacker.attack_path_graph[key]['AttackStage'])}"
                fr"\n{attacker.attack_path_graph[key]['SuccessRate']}")
            dot.node(key, label=f'{node_label}')

        dot.node('Terminal', 'Terminal')

        for key in attacker.attack_path_graph.keys():
            success_node = attacker.attack_path_graph[key]["SuccessPath"]
            failure_node = attacker.attack_path_graph[key]["FailurePath"]
            if success_node == "None": success_node = "Terminal"
            if failure_node == "None": failure_node = "Terminal"

            dot.edge(key, success_node, color='blue')
            dot.edge(key, failure_node, color='red')

        dot.render(directory=model_path, view=False).replace('\\', '/')
        dot.render(directory=model_path, view=False, cleanup=True, filename="AttackPath-circo", engine="circo").replace(
            '\\', '/')

        dot = graphviz.Graph('Network', comment='Network', filename="Network.gv",
                             graph_attr={"label": f"Network of Model{model_number}", "labelloc": "t", "rankdir": "LR",
                                         "compound": "true"})

        dot.format = "png"

        subnet_counter = 0
        for key in network.topology.keys():
            if key == "Internet":
                with dot.subgraph(name=f"cluster_internet") as c:
                    c.attr(label='Internet')
                    c.node('Internet')
            else:
                with dot.subgraph(name=f"cluster_{key.lower()}") as c:
                    c.attr(label=key)
                    host_counter = 0
                    for i in range(network.subnet_hosts[subnet_counter - 1]):
                        c.node(f"({subnet_counter},{host_counter})")
                        host_counter += 1
            subnet_counter += 1

        for i in range(len(network.hosts_configuration)):
            node_label = (
                fr"{network.hosts_configuration[i]['Address']}\n{network.hosts_configuration[i]['Os']}\n{' '.join(network.hosts_configuration[i]['Services'])}"
                fr"\n{' '.join(network.hosts_configuration[i]['Processes'])}\n{network.hosts_configuration[i]['SecurityFactor']}")
            dot.node(network.hosts_configuration[i]['Address'], label=f'{node_label}')

        previous_keys = []
        for key in network.topology.keys():
            for subnet in network.topology[key]:
                if key == "Internet":
                    subnet_number = subnet.removeprefix("Subnet")
                    dot.edge("Internet", f"({subnet_number},0)", lhead=f"cluster_{subnet.lower()}",
                             ltail=f"cluster_{key.lower()}")
                    previous_keys.append(key)
                else:
                    if subnet not in previous_keys:
                        subnet_number1 = key.removeprefix("Subnet")
                        subnet_number2 = subnet.removeprefix("Subnet")
                        dot.edge(f"({subnet_number1},0)", f"({subnet_number2},0)", lhead=f"cluster_{subnet.lower()}",
                                 ltail=f"cluster_{key.lower()}")
                        previous_keys.append(key)

        dot.render(directory=model_path, view=False).replace('\\', '/')

        dot = graphviz.Digraph('BPMN', comment='BPMN', filename="BPMN.gv",
                               graph_attr={"label": f"BPMN of Model{model_number}", "labelloc": "t", "rankdir": "LR",
                                           "compound": "true"})

        dot.format = "png"

        dot.node_attr = {"shape": "rectangle", "style": "rounded,filled", "color": "lightgoldenrodyellow"}

        workflow_counter = 1

        for i in range(bpmn.workflow_numbers):
            dot.node(f"start.{workflow_counter}", label=f"start", shape="circle", color="palegreen1")
            dot.node(f"end.{workflow_counter}", label=f"end", shape="doublecircle", color="orangered")
            workflow_counter += 1

        activity_names = []
        workflow_importance_names = []

        workflow_counter = 1
        for workflow in bpmn.workflows:
            workflow_activities = workflow["Activities"]
            workflow_importance = workflow["Importance"]
            dot.node(f'{str(workflow_importance)}.{workflow_counter}', label=str(workflow_importance), color="gray")
            workflow_importance_names.append(f'{str(workflow_importance)}.{workflow_counter}')
            for activity in workflow_activities:
                if activity == "Start" or activity == "End": continue
                dot.node(f'{activity}.{workflow_counter}', label=activity)
                activity_names.append(f'{activity}.{workflow_counter}')
            workflow_counter += 1

        for resource in bpmn.resources:
            for address in resource["HostAddresses"]:
                dot.node(f"{address}.{resource['Name']}", label=address)

        for mission in bpmn.missions:
            dot.node(fr'{mission["Importance"]}.{mission["Name"]}', label=fr'{mission["Importance"]}', color="gray")
            for activity in mission["Activities"]:
                dot.node(fr'{activity}.{mission["Name"]}', label=fr'{activity}')

        with dot.subgraph(name="cluster_workflow") as c:
            c.attr(label='Workflow', style="dotted")
            workflow_counter = 1
            for i in range(bpmn.workflow_numbers):
                c.node(f"start.{workflow_counter}")
                c.node(f"end.{workflow_counter}")
                workflow_counter += 1

            for importance_name in workflow_importance_names:
                c.node(importance_name)

            for activity_name in activity_names:
                c.node(activity_name)

        for resource in bpmn.resources:
            with dot.subgraph(name=f"cluster_{resource['Name'].lower()}") as c:
                c.attr(label=fr'{resource["Name"]}', style="dotted")
                for address in resource["HostAddresses"]:
                    c.node(f"{address}.{resource['Name']}")

        for i in range(len(bpmn.missions)):
            with dot.subgraph(name=f"cluster_mission{i + 1}") as c:
                c.attr(label=fr'Mission{i + 1}\n{bpmn.missions[i]["Name"]}', style="dotted")
                c.node(fr'{bpmn.missions[i]["Importance"]}.{bpmn.missions[i]["Name"]}')
                for activity in bpmn.missions[i]["Activities"]:
                    c.node(fr'{activity}.{bpmn.missions[i]["Name"]}')

        workflow_counter = 1
        for workflow in bpmn.workflows:
            for i in range(len(workflow["Activities"]) - 1):
                if i == 0:
                    dot.edge(fr"start.{workflow_counter}", fr"{workflow['Importance']}.{workflow_counter}")
                    dot.edge(fr"{workflow['Importance']}.{workflow_counter}",
                             fr"{workflow['Activities'][i + 1]}.{workflow_counter}")
                elif i == len(workflow["Activities"]) - 2:
                    dot.edge(fr"{workflow['Activities'][i]}.{workflow_counter}", fr"end.{workflow_counter}")
                else:
                    dot.edge(fr"{workflow['Activities'][i]}.{workflow_counter}",
                             fr"{workflow['Activities'][i + 1]}.{workflow_counter}")
            workflow_counter += 1

        for activity in activity_names:
            activity_name = activity.split(".")[0]
            desired_activity = [x for x in bpmn.activities if x["Name"] == activity_name][0]
            desired_resource = [x for x in bpmn.resources if x["Name"] == desired_activity['RelatedResource']][0]
            lhead_address = str(desired_resource['HostAddresses'][0]) + "." + desired_resource['Name']
            dot.edge(fr'{activity}', fr'{lhead_address}', style="dashed",
                     lhead=f"cluster_{desired_resource['Name'].lower()}")

        for resource in bpmn.resources:
            if len(resource["Dependencies"]) == 0:
                continue
            for dependency in resource["Dependencies"]:
                desired_resource = [x for x in bpmn.resources if x["Name"] == dependency][0]
                dot.edge(fr'{resource["HostAddresses"][0]}.{resource["Name"]}',
                         fr'{desired_resource["HostAddresses"][0]}.{desired_resource["Name"]}',
                         ltail=f"cluster_{resource['Name'].lower()}",
                         lhead=f"cluster_{desired_resource['Name'].lower()}", style="dashed")

        dot.render(directory=model_path, view=False).replace('\\', '/')

    @staticmethod
    def create_graph_from_file(model_path: str):
        dot = graphviz.Source.from_file(os.path.join(model_path, "BPMN2.gv"))
        dot.format = "png"
        # dot.filename = "BPMN2"
        dot.render(directory="./", view=False).replace('\\', '/')
