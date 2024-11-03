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
#     for file_url in ["BPMN-Network-Model\\Model4\\model4.yml"]:
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
    csa1 = CSA(attacker, network, 0.5, [0.5, 0.5, 0.5, 0.5], False)
    csa2 = CSA(attacker, network, 0.7, [0.5, 0.5, 0.5, 0.5], False)
    csa3 = CSA(attacker, network, 0.9, [0.5, 0.5, 0.5, 0.5], False)
    csa4 = CSA(attacker, network, 0.5, [0.5, 0.5, 0.5, 0.5], True)
    return [csa1, csa2, csa3, csa4]


def fill_attack_paths_in_attacker(attacker, network, first_node: str):
    attacker.create_numbers_of_attack_path(first_node, network.hosts_configuration)


def fill_current_attack_path(attacker, number):
    attack_paths_list = list(attacker.attack_path_list_object.keys())
    attacker.fill_current_attack_path(attack_paths_list[number])


def one_stage_attack(attacker, network, csa_list: list, file, record):
    network_hosts = network.real_change_in_network(attacker, attacker.current_first_node, attacker.current_second_node)
    print(f"Attack Stage From {attacker.current_first_node} to {attacker.current_second_node}", file=file)
    business_factor = network.calculate_business_factor_with_state()
    print(f"real business factor: {round(business_factor, 2)}", file=file)
    record["RealBusinessFactor"] = round(business_factor, 2)
    record["State"] = network_hosts
    for i in range(len(csa_list)):
        csa_current_business_factor = csa_list[i].report_current_state()
        future_real_business_factor, csa_future_business_factor = csa_list[i].report_project_state()
        if future_real_business_factor is not None:
            print(f"future real business factor: {round(future_real_business_factor, 2)}", file=file)
            record["FutureRealBusinessFactor"] = round(future_real_business_factor, 2)
        else:
            print(f"future real business factor: {None}", file=file)
            record["FutureRealBusinessFactor"] = None
        record[f"BusinessFactorCSA{i + 1}"] = round(csa_current_business_factor, 2)
        print(f"business factor of csa number {i + 1}: {round(csa_current_business_factor, 2)}", file=file)
        record[f"FutureBusinessFactorCSA{i + 1}"] = round(csa_future_business_factor, 2)
        print(f"future business factor of csa number {i + 1}: {round(csa_future_business_factor, 2)}", file=file)
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

    csa_list_raw_data = []
    for i in range(csa_numbers):
        csa_list_raw_data.append({"csa_number": i + 1, "evaluate_now_list": [], "evaluate_future_list": []})
    for record in records:
        real_business_factor = record["RealBusinessFactor"]
        for i in range(csa_numbers):
            business_factor_csa = record[f"BusinessFactorCSA{i + 1}"]
            future_business_factor_csa = record[f"FutureBusinessFactorCSA{i + 1}"]
            difference = abs(real_business_factor - business_factor_csa)
            future_business_factor = record["FutureRealBusinessFactor"]
            if future_business_factor is not None:
                future_difference = abs(future_business_factor - future_business_factor_csa)
                related_csa = [x for x in csa_list_raw_data if x["csa_number"] == i + 1][0]
                related_csa["evaluate_now_list"].append(difference)
                related_csa["evaluate_future_list"].append(future_difference)
            else:
                related_csa = [x for x in csa_list_raw_data if x["csa_number"] == i + 1][0]
                related_csa["evaluate_now_list"].append(difference)

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

    return evaluate_csa_list_with_zero, evaluate_csa_list_without_zero, evaluate_csa_list_with_zero_normalized, evaluate_csa_list_without_zero_normalized


def run_simulation(mongo, one_model_json, attack_path_file_address: str, csa_result_file_address: str):
    mongo.add_model_number(one_model_json["ModelNumber"])
    mongo_helper.delete_all_records_of_model()

    if os.path.exists(attack_path_file_address):
        os.remove(attack_path_file_address)

    if os.path.exists(csa_result_file_address):
        os.remove(csa_result_file_address)

    attack_path_file = open(attack_path_file_address, "a")
    csa_result_file = open(csa_result_file_address, "a")

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

    for i in tqdm(range(len(attack_path_list))):
        fill_current_attack_path(attacker, i)
        string_attack_path = json.dumps(attack_path_list[i]).replace("\\", "").replace('"[', "[").replace(']"', "]")
        for j in range(attacker.attack_path_list_object[string_attack_path]):
            print(f"Attack Path Is: {string_attack_path} And Number Is: {j + 1}", file=csa_result_file)
            network.initial_state_network()
            for csa in csa_list:
                csa.initialize_state(network)
            for k in range(len(attacker.current_attack_path) - 1):
                record = {"AttackPath": string_attack_path, "AttackPathNumber": j + 1}
                attacker.current_first_node = attacker.current_attack_path[k]
                attacker.current_second_node = attacker.current_attack_path[k + 1]
                record["FirstNode"] = attacker.current_first_node
                record["SecondNode"] = attacker.current_second_node
                one_stage_attack(attacker, network, csa_list, csa_result_file, record)

    csa_result_file.close()


mongo_helper = MongoHelper()
jsons = import_yml_files_to_json()

for one_json in jsons:
    attack_path_address = os.path.join(one_json["DirectoryPath"], "AttackPath.txt")
    csa_detailed_result_address = os.path.join(one_json["DirectoryPath"], "CSADetailedResult.txt")
    csa_result_address = os.path.join(one_json["DirectoryPath"], "CSAResult.txt")
    run_simulation(mongo_helper, one_json, attack_path_address, csa_detailed_result_address)
    result = evaluate_csa_s(mongo_helper, one_json)
    pprint(result, open(csa_result_address, "w"))
