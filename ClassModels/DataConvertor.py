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
        return " ".join(one_list)

    @staticmethod
    def create_model_csv(bpmn: BPMN, network: NetworkState, attacker: Attacker, model_path:str):
        resource_pool_path = os.path.join(model_path, 'ResourcePools.csv')
        attacker_path = os.path.join(model_path, 'Attack.csv')
        host_path = os.path.join(model_path, 'Hosts.csv')
        mission_path = os.path.join(model_path, 'Mission.csv')
        processes_path = os.path.join(model_path, 'Processes.csv')
        subnets_path = os.path.join(model_path, 'Subnets.csv')
        workflow_path = os.path.join(model_path, 'Workflows.csv')

        resource_pool_key = ["Name", "ResourceNumber", "Resources", "Dependencies", "SubnetNumber"]
        resource_pool_value = []
        for row in bpmn.resource_pools:
            new_field = [row["Name"], row["ResourceNumber"], DataConvertor.convert_list_to_string(row["Resources"]),
                         DataConvertor.convert_list_to_string(row["Dependencies"]), row["RelatedSubnet"]]
            resource_pool_value.append(new_field)

        with open(resource_pool_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(resource_pool_key)
            csvwriter.writerows(resource_pool_value)

        process_key = ["Name", "ResourcePool"]
        process_value = []
        for row in bpmn.processes:
            new_field = [row["Name"], row["RelatedResourcePool"]]
            process_value.append(new_field)

        with open(processes_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(process_key)
            csvwriter.writerows(process_value)

        workflow_key = ["Path", "Priority"]
        workflow_value = []
        for row in bpmn.workflow_paths:
            new_field = [DataConvertor.convert_list_to_string(row["Path"]), row["Priority"]]
            workflow_value.append(new_field)

        with open(workflow_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(workflow_key)
            csvwriter.writerows(workflow_value)

        mission_key = ["Name", "Processes", "Priority"]
        mission_value = []
        for row in bpmn.missions:
            new_field = [row["Name"], DataConvertor.convert_list_to_string(row["Processes"]), row["Priority"]]
            mission_value.append(new_field)

        with open(mission_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(mission_key)
            csvwriter.writerows(mission_value)


        subnet_key = ["Name", "HostNumbers", "Relations"]
        subnet_value = [["Internet", "0"]]
        subnet_value[0].append(DataConvertor.convert_list_to_string(network.topology["Internet"]))
        for i in range(len(network.subnet_hosts)):
            new_field = [f"Subnet{i + 1}", str(network.subnet_hosts[i]), DataConvertor.convert_list_to_string(network.topology["Subnet" + str(i + 1)])]
            subnet_value.append(new_field)

        with open(subnets_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', lineterminator='\n')
            csvwriter.writerow(subnet_key)
            csvwriter.writerows(subnet_value)

        host_key = ["Address", "OS", "Services", "Processes", "SecurityFactor"]
        host_value = []
        for i in range(len(network.hosts_configuration)):
            new_field = [network.hosts_configuration[i]["Address"].replace(",", " "), network.hosts_configuration[i]["Os"],
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
            new_field = [key, attacker.attack_path_graph[key]["ExploitName"], attacker.attack_path_graph[key]["Vulnerability"],
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
    def create_result_csv(model_path:str, model_number:int, mongo_helper: MongoHelper):
        result_path = os.path.join(model_path, 'Result.csv')

        mongo_helper.add_model_number(model_number)

        records = mongo_helper.find_all_record_of_model()
        one_record = records[0]

        result_key = ["AttackPath", "AttackPathNumber", "FirstNode", "SecondNode", "RealBusinessFactor", "FutureRealBusinessFactor"]

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
    def create_graph(model_path:str, model_number: int, bpmn: BPMN, network: NetworkState, attacker: Attacker):

        dot = graphviz.Digraph('AttackPathModel', comment='Attack Path', filename="AttackPath.gv",
                               graph_attr={"label": f"Attack Path of Model{model_number}", "labelloc": "t"})
        dot.format = "png"

        for key in attacker.attack_path_graph.keys():
            node_label = (fr"{key}\n{attacker.attack_path_graph[key]['ExploitName']}\n{attacker.attack_path_graph[key]['Vulnerability']}"
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
        dot.render(directory=model_path, view=False, cleanup=True, filename="AttackPath-circo", engine="circo").replace('\\', '/')

        dot = graphviz.Graph('Network', comment='Network', filename="Network.gv",
                               graph_attr={"label": f"Network of Model{model_number}", "labelloc": "t", "rankdir": "LR",
                                           "compound": "true"})

        dot.format = "png"

        #Numbers = ["one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"]
        #alphabet = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"]

        subnet_counter = 0
        #alphabet_counter = 0
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
                    dot.edge("Internet", f"({subnet_number},0)", lhead=f"cluster_{subnet.lower()}", ltail=f"cluster_{key.lower()}")
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

        start_names = []
        end_names = []

        for i in range(bpmn.bpmn_json['WorkFlows']["PathNumbers"]):
            if i == 0:
                dot.node(f"start", label=f"start", shape="circle", color="palegreen1")
                dot.node(f"end", label=f"end", shape="doublecircle", color="orangered")
                start_names.append(f"start")
                end_names.append(f"end")
            else:
                dot.node(f"start{i + 1}", label= f"start{i + 1}" , shape="circle", color="palegreen1")
                dot.node(f"end{i + 1}", label= f"end{i + 1}", shape="doublecircle", color="orangered")
                start_names.append(f"start{i + 1}")
                end_names.append(f"end{i + 1}")


        for process in bpmn.processes:
            dot.node(process["Name"], label=process["Name"])

        for resource_pool in bpmn.resource_pools:
            for resource in resource_pool["Resources"]:
                dot.node(resource, label=resource)

        for mission in bpmn.missions:
            dot.node(mission["Name"], label=fr'{mission["Name"]}\n{mission["Priority"]}')

        start_gateway_names = []
        end_gateway_names = []

        def add_gateway_of_path(path, path_number, previous_string:str, start_gateway_names:list, end_gateway_names:list):

            gateway_strings = []
            for key in path["OrderedKeys"]:
                if key.find("GateWays") != -1:
                    gateway_strings.append(key)

            for j in range(len(gateway_strings)):
                dot.node(f"{previous_string}path{path_number}{gateway_strings[j].lower()}start", label=r"+", shape="diamond")
                dot.node(f"{previous_string}path{path_number}{gateway_strings[j].lower()}end", label=r"+", shape="diamond")
                start_gateway_names.append(f"{previous_string}path{path_number}{gateway_strings[j].lower()}start")
                end_gateway_names.append(f"{previous_string}path{path_number}{gateway_strings[j].lower()}end")
                for k in range(path[gateway_strings[j]]["PathNumbers"]):
                    add_gateway_of_path(path[gateway_strings[j]][f"Path{k + 1}"], k+1,previous_string + f"path{path_number}{gateway_strings[j].lower()}",
                                        start_gateway_names, end_gateway_names)

        for i in range(bpmn.bpmn_json['WorkFlows']["PathNumbers"]):
            add_gateway_of_path(bpmn.bpmn_json['WorkFlows'][f"Path{i+1}"], i+1,"", start_gateway_names, end_gateway_names)


        with dot.subgraph(name="cluster_workflow") as c:
            c.attr(label='Workflow', style="dotted")
            for start_name in start_names:
                c.node(start_name)

            for end_name in end_names:
                c.node(end_name)

            for process in bpmn.processes:
                c.node(process["Name"])

            for start_gateway_names in start_gateway_names:
                c.node(start_gateway_names)

            for end_gateway_names in end_gateway_names:
                c.node(end_gateway_names)

        for resource_pool in bpmn.resource_pools:
            with dot.subgraph(name=f"cluster_{resource_pool['Name'].lower()}") as c:
                c.attr(label=fr'{resource_pool["Name"]}\n{"Subnet" + str(resource_pool["RelatedSubnet"])}', style="dotted")
                for resource in resource_pool["Resources"]:
                    c.node(resource)

        for i in range(len(bpmn.missions)):
            with dot.subgraph(name=f"cluster_mission{i + 1}") as c:
                c.attr(label=f'Mission{i+1}', style="dotted")
                c.node(bpmn.missions[i]["Name"])


        # for workflow in bpmn.workflow_paths:
        #     for i in range(len(workflow["Path"])):
        #         if workflow["Path"][i] == "Start":
        #             dot.edge(workflow["Path"][i].lower(), workflow["Path"][i+1])
        #             continue
        #         if workflow["Path"][i] == "End":
        #             continue
        #         if workflow["Path"][i + 1] == "End":
        #             dot.edge(workflow["Path"][i], workflow["Path"][i+1].lower())
        #             continue
        #         dot.edge(workflow["Path"][i], workflow["Path"][i+1])

        for process in bpmn.processes:
            desired_resource_pool = [x for x in bpmn.resource_pools if x["Name"] == process['RelatedResourcePool']][0]
            dot.edge(process["Name"], desired_resource_pool["Resources"][0], style="dashed", lhead=f"cluster_{desired_resource_pool['Name'].lower()}")

        for resource_pool in bpmn.resource_pools:
            if len(resource_pool["Dependencies"]) == 0:
                continue
            for dependency in resource_pool["Dependencies"]:
                desired_resource_pool = [x for x in bpmn.resource_pools if x["Name"] == dependency][0]
                dot.edge(resource_pool["Resources"][0], desired_resource_pool["Resources"][0], ltail=f"cluster_{resource_pool['Name'].lower()}", lhead= f"cluster_{desired_resource_pool['Name'].lower()}", style="dashed")

        for i in range(len(bpmn.missions)):
            for process in bpmn.missions[i]["Processes"]:
                dot.edge(process, bpmn.missions[i]["Name"], style="dashed", lhead=f"cluster_mission{i+1}")


        dot.render(directory=model_path, view=False).replace('\\', '/')


    @staticmethod
    def create_graph_from_file(model_path: str):
        dot = graphviz.Source.from_file(os.path.join(model_path, "BPMN2.gv"))
        dot.format = "png"
        #dot.filename = "BPMN2"
        dot.render(directory="./", view=False).replace('\\', '/')









