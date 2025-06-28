import glob
import json
import yaml
import os
import statistics
from ClassModels.BPMN import BPMN
from ClassModels.CSASimulator import CSA
from ClassModels.MongoHelper import MongoHelper
from ClassModels.NetworkState import NetworkState
from ClassModels.Attacker import Attacker
from pprint import pprint
from tqdm import tqdm
from itertools import pairwise


def import_yml_files_to_json():
    json_list = []
    for file_url in glob.glob("BPMN-Network-Model\\*\\*.yml"):
        with open(file_url, 'r') as file:
            json = yaml.safe_load(file)
            json["ModelNumber"] = int(file_url.split("\\")[1].removeprefix("Model"))
            json["DirectoryPath"] = os.path.dirname(file_url)
            json_list.append(json)
    return json_list

# def import_yml_files_to_json():
#     json_list = []
#     #for file_url in ["BPMN-Network-Model\\Model1\\model1.yml","BPMN-Network-Model\\Model2\\model2.yml","BPMN-Network-Model\\Model3\\model3.yml"]:
#     for file_url in ["BPMN-Network-Model\\Model1\\model1.yml"]:
#         with open(file_url, 'r') as file:
#             json = yaml.safe_load(file)
#             json["ModelNumber"] = int(file_url.split("\\")[1].removeprefix("Model"))
#             json["DirectoryPath"] = os.path.dirname(file_url)
#             json_list.append(json)
#     return json_list


def initialize_elements(one_json):
    bpmn = BPMN(one_json["BPMN"])
    network = NetworkState(one_json["Network"])
    attacker = Attacker(one_json["Attack"])

    network.add_host_importance(bpmn)
    return bpmn, network, attacker


def initialize_csa_s(attacker, network):
    csa1 = CSA(attacker, network, 0.3, False)
    csa2 = CSA(attacker, network, 0.5, False)
    csa3 = CSA(attacker, network, 0.7, False)
    csa4 = CSA(attacker, network, 0.5, True)
    return [csa1, csa2, csa3, csa4]


def fill_attack_paths_in_attacker(attacker, network, first_node: str):
    attacker.create_numbers_of_attack_path(first_node, network.hosts_configuration)


def fill_current_attack_path(attacker, number):
    attack_paths_list = list(attacker.attack_path_list_object.keys())
    attacker.fill_current_attack_path(attack_paths_list[number])


def one_stage_attack(attacker, network, csa_list: list, record):
    network_hosts = network.real_change_in_network(attacker, attacker.current_first_node, attacker.current_second_node)
    business_factor = network.calculate_business_factor_with_state()
    record["RealBusinessFactor"] = round(business_factor, 2)
    record["State"] = network_hosts
    for i in range(len(csa_list)):
        csa_list[i].update_current_attack_path()
        csa_list[i].predication_of_near_nodes()
        csa_current_business_factor = csa_list[i].report_current_state()
        future_real_business_factor, csa_future_business_factor = csa_list[i].report_project_state()
        predict_attack_graph = csa_list[i].report_project_attack_graph()
        string_attack_path = json.dumps(predict_attack_graph).replace("\\", "").replace('"[', "[").replace(']"', "]").replace('"', "'")
        if future_real_business_factor is not None:
            record["FutureRealBusinessFactor"] = round(future_real_business_factor, 2)
        else:
            record["FutureRealBusinessFactor"] = None

        record[f"CSA{i + 1}"] = {"BusinessFactor": round(csa_current_business_factor, 2),
                                 "FirstNode": csa_list[i].prediction_of_first_node,
                                 "SecondNode": csa_list[i].prediction_of_second_node,
                                 "PredictAttackGraph": string_attack_path}

        if csa_future_business_factor != None:
            record[f"CSA{i + 1}"]["FutureBusinessFactor"] = round(csa_future_business_factor, 2)
        else:
            record[f"CSA{i + 1}"]["FutureBusinessFactor"] = None
    mongo_helper.add_one_record(record)


def evaluate_csa_s(mongo, one_model_json):
    mongo.add_model_number(one_model_json["ModelNumber"])

    bpmn, network, attacker = initialize_elements(one_model_json)
    csa_list = initialize_csa_s(attacker, network)
    csa_numbers = len(csa_list)
    business_factor = bpmn.business_importance
    records = mongo.find_all_record_of_model()

    def exclude_zero_from_list(one_list):
        return_list = []
        for item in one_list:
            if item == 0:
                continue
            return_list.append(item)
        return return_list

    def difference_of_two_attack_path(first_attack_path, second_attack_path):
        first_attack_path_list = json.loads(first_attack_path.replace("'", '"'))
        second_attack_path = json.loads(second_attack_path.replace("'", '"'))
        exclude_node_numbers = 0
        for node in first_attack_path_list:
            node = node.split(":")[0]
            if node not in second_attack_path:
                if node == "None" or node == "None:S" or node == "None:F": continue
                exclude_node_numbers += 1
        for node in second_attack_path:
            node = node.split(":")[0]
            if node not in first_attack_path_list:
                if node == "None" or node == "None:S" or node == "None:F": continue
                exclude_node_numbers += 1

        exclude_edge_numbers = 0
        for edge in pairwise(first_attack_path_list):
            if edge not in pairwise(second_attack_path):
                exclude_edge_numbers += 1

        for edge in pairwise(second_attack_path):
            if edge not in pairwise(first_attack_path_list):
                exclude_edge_numbers += 1

        return exclude_node_numbers * 0.5 + exclude_edge_numbers * 1

    csa_list_raw_data = []
    for i in range(csa_numbers):
        csa_list_raw_data.append({"csa_number": i + 1, "evaluate_now_list": [], "evaluate_future_list": [], "evaluate_first_node": 0,
                                  "evaluate_second_node": 0, "evaluate_attack_path": []})
    for record in records:
        real_business_factor = record["RealBusinessFactor"]
        real_first_node = record["FirstNode"]
        real_second_node = record["SecondNode"]
        real_attack_path = record["AttackPath"]
        for i in range(csa_numbers):
            business_factor_csa = record[f"CSA{i + 1}"][f"BusinessFactor"]
            future_business_factor_csa = record[f"CSA{i + 1}"][f"FutureBusinessFactor"]
            first_node_csa = record[f"CSA{i + 1}"]["FirstNode"]
            second_node_csa = record[f"CSA{i + 1}"]["SecondNode"]
            attack_path_csa = record[f"CSA{i + 1}"]["PredictAttackGraph"]
            difference = abs(real_business_factor - business_factor_csa)
            future_business_factor = record["FutureRealBusinessFactor"]
            related_csa = [x for x in csa_list_raw_data if x["csa_number"] == i + 1][0]
            if real_first_node == first_node_csa: related_csa["evaluate_first_node"] += 1
            if real_second_node == second_node_csa: related_csa["evaluate_second_node"] += 1
            related_csa["evaluate_attack_path"].append(difference_of_two_attack_path(real_attack_path, attack_path_csa))
            if future_business_factor is not None and future_business_factor_csa is not None:
                future_difference = abs(future_business_factor - future_business_factor_csa)
                related_csa["evaluate_now_list"].append(difference)
                related_csa["evaluate_future_list"].append(future_difference)
            else:
                related_csa["evaluate_now_list"].append(difference)

    evaluate_csa_attacker = []
    evaluate_csa_list_with_zero = []
    evaluate_csa_list_without_zero = []
    evaluate_csa_list_with_zero_normalized = []
    evaluate_csa_list_without_zero_normalized = []
    for i in range(len(csa_list_raw_data)):
        one_csa_evaluate = {"csa_number": i + 1, "evaluate_now": statistics.mean(
            exclude_zero_from_list(csa_list_raw_data[i]["evaluate_now_list"])),
                            "evaluate_future": statistics.mean(
                                exclude_zero_from_list(csa_list_raw_data[i]["evaluate_future_list"]))}
        evaluate_csa_list_without_zero.append(one_csa_evaluate)

    for i in range(len(csa_list_raw_data)):
        one_csa_evaluate = {"csa_number": i + 1, "evaluate_first_node_correctness": csa_list_raw_data[i]["evaluate_first_node"] * 1.0 / len(csa_list_raw_data[i]["evaluate_attack_path"]) * 100,
                            "evaluate_second_node_correctness": csa_list_raw_data[i]["evaluate_second_node"] * 1.0 / len(csa_list_raw_data[i]["evaluate_attack_path"]) * 100,
                            "evaluate_attack_path": statistics.mean(csa_list_raw_data[i]["evaluate_attack_path"])}
        evaluate_csa_attacker.append(one_csa_evaluate)

    for i in range(len(csa_list_raw_data)):
        one_csa_evaluate = {"csa_number": i + 1,
                            "evaluate_now": statistics.mean(csa_list_raw_data[i]["evaluate_now_list"]),
                            "evaluate_future": statistics.mean(csa_list_raw_data[i]["evaluate_future_list"])}
        evaluate_csa_list_with_zero.append(one_csa_evaluate)

    for i in range(len(evaluate_csa_list_without_zero)):
        one_csa_evaluate = {"csa_number": i + 1,
                            "evaluate_now": evaluate_csa_list_without_zero[i]["evaluate_now"] * 100.0 / business_factor,
                            "evaluate_future": evaluate_csa_list_without_zero[i][
                                                   "evaluate_future"] * 100.0 / business_factor}
        evaluate_csa_list_without_zero_normalized.append(one_csa_evaluate)

    for i in range(len(evaluate_csa_list_with_zero)):
        one_csa_evaluate = {"csa_number": i + 1,
                            "evaluate_now": evaluate_csa_list_with_zero[i]["evaluate_now"] * 100.0 / business_factor,
                            "evaluate_future": evaluate_csa_list_with_zero[i][
                                                   "evaluate_future"] * 100.0 / business_factor}
        evaluate_csa_list_with_zero_normalized.append(one_csa_evaluate)

    return [evaluate_csa_attacker, evaluate_csa_list_with_zero, evaluate_csa_list_without_zero, evaluate_csa_list_with_zero_normalized, evaluate_csa_list_without_zero_normalized]


def run_simulation(mongo, one_model_json, attack_path_file_address: str):

    def progress_bar(curr, N, width=10, bars=u'▉▊▋▌▍▎▏ '[::-1],
                   full='█', empty=' '):
        p = curr / N
        nfull = int(p * width)
        return "{:>3.0%} |{}{}{}| {:>2}/{}" \
            .format(p, full * nfull,
                    bars[int(len(bars) * ((p * width) % 1))],
                    empty * (width - nfull - 1),
                    curr, N)

    mongo.add_model_number(one_model_json["ModelNumber"])
    mongo_helper.delete_all_records_of_model()

    if os.path.exists(attack_path_file_address):
        os.remove(attack_path_file_address)

    attack_path_file = open(attack_path_file_address, "a")

    bpmn, network, attacker = initialize_elements(one_model_json)
    csa_list = initialize_csa_s(attacker, network)

    first_node = "A"

    attacker.create_all_paths()
    attacker.calculate_probability_of_longest_path(network.hosts_configuration, first_node)
    #attacker.calculate_probability_of_most_successful_path(network.hosts_configuration, first_node)
    attacker.calculate_appropriate_attack_path_number()

    fill_attack_paths_in_attacker(attacker, network, first_node)

    pprint(attacker.attack_path_list_object, attack_path_file)
    attack_path_file.close()

    attack_path_list = list(attacker.attack_path_list_object)

    pbar = tqdm(range(len(attack_path_list)), bar_format='{l_bar}{bar:10}{r_bar}{bar:-10b}')

    for i in pbar:
        fill_current_attack_path(attacker, i)
        string_attack_path = json.dumps(attack_path_list[i]).replace("\\", "").replace('"[', "[").replace(']"', "]")
        for j in range(attacker.attack_path_list_object[string_attack_path]):
            attacker.current_current_attack_path = []
            network.initial_state_network()
            for csa in csa_list:
                csa.initialize_state(network)
            for k in range(len(attacker.current_attack_path) - 1):
                string_current_attack_path = json.dumps(attacker.current_current_attack_path).replace("\\", "").replace('"[', "[").replace(']"', "]")
                record = {"AttackPath": string_attack_path, "AttackPathNumber": j + 1, "CurrentAttackPath": string_current_attack_path}
                attacker.current_first_node = attacker.current_attack_path[k]
                attacker.current_second_node = attacker.current_attack_path[k + 1]
                record["FirstNode"] = attacker.current_first_node
                record["SecondNode"] = attacker.current_second_node
                one_stage_attack(attacker, network, csa_list, record)
                attacker.current_current_attack_path.append(attacker.current_first_node)
            pbar.set_postfix_str(progress_bar(j, attacker.attack_path_list_object[string_attack_path]))



mongo_helper = MongoHelper()
jsons = import_yml_files_to_json()

for one_json in jsons:
    attack_path_address = os.path.join(one_json["DirectoryPath"], "AttackPath.txt")
    csa_result_address = os.path.join(one_json["DirectoryPath"], "CSAResult.txt")
    run_simulation(mongo_helper, one_json, attack_path_address)
    result = evaluate_csa_s(mongo_helper, one_json)
    print(json.dumps(result), file=open(csa_result_address, "w"))
