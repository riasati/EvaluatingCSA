import glob
import json
import yaml
from ClassModels.BPMN import BPMN
from ClassModels.CSASimulator import CSA
from ClassModels.MongoHelper import MongoHelper
from ClassModels.NetworkState import NetworkState
from ClassModels.Attacker import Attacker
from pprint import pprint



def import_yml_files_to_json():
    json_list = []
    for file_url in glob.glob("BPMN-Network-Model\\*\\*.yml"):
        with open(file_url, 'r') as file:
            json = yaml.safe_load(file)
            json_list.append(json)
    return json_list


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


def fill_attack_paths_in_attacker(attacker, network, first_node: str, number: int):
    attacker.create_numbers_of_attack_path(first_node, network.hosts_configuration, number)


def fill_current_attack_path(attacker, number):
    attack_paths_list = list(attacker.attack_path_list_object.keys())
    attacker.fill_current_attack_path(attack_paths_list[number])


def one_stage_attack(attacker, network, csa_list: list, file, record):
    network.real_change_in_network(attacker, attacker.current_first_node, attacker.current_second_node)
    print(f"Attack Stage From {attacker.current_first_node} to {attacker.current_second_node}", file=file)
    business_factor = network.calculate_business_factor_with_state()
    print(f"real business factor: {round(business_factor, 2)}", file=file)
    record["RealBusinessFactor"] = round(business_factor, 2)
    for i in range(len(csa_list)):
        csa_current_business_factor = csa_list[i].report_current_state()
        future_real_business_factor, csa_future_business_factor = csa_list[i].report_project_state()
        if future_real_business_factor is not None:
            print(f"future real business factor: {round(future_real_business_factor, 2)}", file=file)
            record["FutureRealBusinessFactor"] = round(future_real_business_factor, 2)
        else:
            print(f"future real business factor: {None}", file=file)
            record["FutureRealBusinessFactor"] = None
        record[f"BusinessFactorCSA{i+1}"] = round(csa_current_business_factor, 2)
        print(f"business factor of csa number {i + 1}: {round(csa_current_business_factor, 2)}", file=file)
        record[f"FutureBusinessFactorCSA{i + 1}"] = round(csa_future_business_factor, 2)
        print(f"future business factor of csa number {i + 1}: {round(csa_future_business_factor, 2)}", file=file)
    mongo_helper.add_one_record(record)


def evaluate_csa_s(records, csa_numbers: int, business_factor: float):
    import statistics
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
        one_csa_evaluate = {"csa_number": i + 1, "evaluate_now": statistics.mean(exclude_zero_from_list(csa_list_raw_data[i]["evaluate_now_list"])),
                            "evaluate_future": statistics.mean(exclude_zero_from_list(csa_list_raw_data[i]["evaluate_future_list"]))}
        evaluate_csa_list_without_zero.append(one_csa_evaluate)

    for i in range(len(csa_list_raw_data)):
        one_csa_evaluate = {"csa_number": i + 1, "evaluate_now": statistics.mean(csa_list_raw_data[i]["evaluate_now_list"]),
                            "evaluate_future": statistics.mean(csa_list_raw_data[i]["evaluate_future_list"])}
        evaluate_csa_list_with_zero.append(one_csa_evaluate)

    for i in range(len(evaluate_csa_list_without_zero)):
        one_csa_evaluate = {"csa_number": i + 1,
                            "evaluate_now": evaluate_csa_list_without_zero[i]["evaluate_now"] * 100.0 / business_factor,
                            "evaluate_future": evaluate_csa_list_without_zero[i]["evaluate_future"] * 100.0 / business_factor}
        evaluate_csa_list_without_zero_normalized.append(one_csa_evaluate)

    for i in range(len(evaluate_csa_list_with_zero)):
        one_csa_evaluate = {"csa_number": i + 1,
                            "evaluate_now": evaluate_csa_list_with_zero[i]["evaluate_now"] * 100.0 / business_factor,
                            "evaluate_future": evaluate_csa_list_with_zero[i]["evaluate_future"] * 100.0 / business_factor}
        evaluate_csa_list_with_zero_normalized.append(one_csa_evaluate)

    return evaluate_csa_list_with_zero, evaluate_csa_list_without_zero, evaluate_csa_list_with_zero_normalized, evaluate_csa_list_without_zero_normalized

def exclude_zero_from_list(one_list):
    return_list = []
    for item in one_list:
        if item == 0:
            continue
        return_list.append(item)
    return return_list




mongo_helper = MongoHelper()
mongo_helper.add_model_number(1)
#mongo_helper.delete_all_records()

records = mongo_helper.find_all_record_of_model()
evaluate_csa_s(records, 4, 16)

# file = open("attack paths.txt", "a")
# file2 = open("csa results.txt", "a")
#
# json_list = import_yml_files_to_json()
# one_json = json_list[0]
# bpmn, network, attacker = initialize_elements(one_json)
# csa_list = initialize_csa_s(attacker, network)
#
# fill_attack_paths_in_attacker(attacker, network, "A", 10000)
# pprint(attacker.attack_path_list_object, file)
# file.close()
# attack_path_list = list(attacker.attack_path_list_object)
# for i in range(len(attack_path_list)):
#     fill_current_attack_path(attacker, i)
#     string_attack_path = json.dumps(attack_path_list[i]).replace("\\", "").replace('"[', "[").replace(']"', "]")
#     for j in range(attacker.attack_path_list_object[string_attack_path]):
#         print(f"Attack Path Is: {string_attack_path} And Number Is: {j + 1}", file=file2)
#         network.initial_state_network()
#         for csa in csa_list:
#             csa.initialize_state(network)
#         for k in range(len(attacker.current_attack_path) - 1):
#             record = {}
#             record["AttackPath"] = string_attack_path
#             record["AttackPathNumber"] = j + 1
#             attacker.current_first_node = attacker.current_attack_path[k]
#             attacker.current_second_node = attacker.current_attack_path[k + 1]
#             record["FirstNode"] = attacker.current_first_node
#             record["SecondNode"] = attacker.current_second_node
#             one_stage_attack(attacker, network, csa_list, file2, record)
#
# file2.close()



# fill_current_attack_path(attacker, 0)
#
# for i in range(len(attacker.current_attack_path) - 1):
#     attacker.current_first_node = attacker.current_attack_path[i]
#     attacker.current_second_node = attacker.current_attack_path[i + 1]
#     one_stage_attack(attacker, network, csa_list)




# a = json.load(open('config.json'))
# b = BPMN(a["BPMN"])
# c = NetworkState(a["Network"])
# d = Attacker(a["Attack"])

# b.calculate_business_importance()
# b.calculate_process_priority()

# c.add_host_importance(b)
#
# z1 = CSA(d, c, 0.5, [50, 50, 50, 50], False)
# z2 = CSA(d, c, 0.7, [50, 50, 50, 50], False)
# z3 = CSA(d, c, 0.9, [50, 50, 50, 50], False)
# z4 = CSA(d, c, 0.5, [50, 50, 50, 50], True)

# pprint(b.resource_pools)
# pprint(b.processes)
# pprint(b.workflow_paths)
# pprint(b.missions)

# e = d.get_success_attack_node("A")
# f = d.get_failure_attack_node("A")
# g = d.get_host_related_security_factor("A", c.hosts_configuration)
# h = d.is_attack_successful("A", g)
# i = d.create_attack_path("A", c.hosts_configuration, [])

# d.create_numbers_of_attack_path("A", c.hosts_configuration, 10000)
# # pprint(d.attack_path_list_object)
# print(d.attack_path_list_object.keys())
# # d.fill_current_attack_path(list(d.attack_path_list_object.keys())[1])
# d.fill_current_attack_path('["A", "C", "E", "G", "I", "K", "None"]')
#
# e = c.real_change_in_network(d, "A", "C")
# d.current_first_node = "A"
# d.current_second_node = "C"
# print("Attack From A to C")
# e = c.calculate_business_factor_with_state()
# print("real business factor: ", e)
# e1 = z1.report_current_state()
# print("first business factor: ", e1)
# e11 = z1.report_project_state()
# print("first business factor future: ", e11)
# e2 = z2.report_current_state()
# print("second business factor: ", e2)
# e22 = z2.report_project_state()
# print("second business factor future: ", e22)
# e3 = z3.report_current_state()
# print("third business factor: ", e3)
# e33 = z3.report_project_state()
# print("third business factor future: ", e33)
# e4 = z4.report_current_state()
# print("forth business factor: ", e4)
# e44 = z4.report_project_state()
# print("forth business factor future: ", e44)
#
# e = c.real_change_in_network(d, "C", "E")
# d.current_first_node = "C"
# d.current_second_node = "E"
# print("Attack From C to E")
# e = c.calculate_business_factor_with_state()
# print("real business factor: ", e)
# e1 = z1.report_current_state()
# print("first business factor: ", e1)
# e11 = z1.report_project_state()
# print("first business factor future: ", e11)
# e2 = z2.report_current_state()
# print("second business factor: ", e2)
# e22 = z2.report_project_state()
# print("second business factor future: ", e22)
# e3 = z3.report_current_state()
# print("third business factor: ", e3)
# e33 = z3.report_project_state()
# print("third business factor future: ", e33)
# e4 = z4.report_current_state()
# print("forth business factor: ", e4)
# e44 = z4.report_project_state()
# print("forth business factor future: ", e44)
#
# e = c.real_change_in_network(d, "E", "G")
# d.current_first_node = "E"
# d.current_second_node = "G"
# print("Attack From E to G")
# e = c.calculate_business_factor_with_state()
# print("real business factor: ", e)
# e1 = z1.report_current_state()
# print("first business factor: ", e1)
# e11 = z1.report_project_state()
# print("first business factor future: ", e11)
# e2 = z2.report_current_state()
# print("second business factor: ", e2)
# e22 = z2.report_project_state()
# print("second business factor future: ", e22)
# e3 = z3.report_current_state()
# print("third business factor: ", e3)
# e33 = z3.report_project_state()
# print("third business factor future: ", e33)
# e4 = z4.report_current_state()
# print("forth business factor: ", e4)
# e44 = z4.report_project_state()
# print("forth business factor future: ", e44)
#
# e = c.real_change_in_network(d, "G", "I")
# d.current_first_node = "G"
# d.current_second_node = "I"
# print("Attack From G to I")
# e = c.calculate_business_factor_with_state()
# print("real business factor: ", e)
# e1 = z1.report_current_state()
# print("first business factor: ", e1)
# e11 = z1.report_project_state()
# print("first business factor future: ", e11)
# e2 = z2.report_current_state()
# print("second business factor: ", e2)
# e22 = z2.report_project_state()
# print("second business factor future: ", e22)
# e3 = z3.report_current_state()
# print("third business factor: ", e3)
# e33 = z3.report_project_state()
# print("third business factor future: ", e33)
# e4 = z4.report_current_state()
# print("forth business factor: ", e4)
# e44 = z4.report_project_state()
# print("forth business factor future: ", e44)
#
# e = c.real_change_in_network(d, "I", "K")
# d.current_first_node = "I"
# d.current_second_node = "K"
# print("Attack From I to K")
# e = c.calculate_business_factor_with_state()
# print("real business factor: ", e)
# e1 = z1.report_current_state()
# print("first business factor: ", e1)
# e11 = z1.report_project_state()
# print("first business factor future: ", e11)
# e2 = z2.report_current_state()
# print("second business factor: ", e2)
# e22 = z2.report_project_state()
# print("second business factor future: ", e22)
# e3 = z3.report_current_state()
# print("third business factor: ", e3)
# e33 = z3.report_project_state()
# print("third business factor future: ", e33)
# e4 = z4.report_current_state()
# print("forth business factor: ", e4)
# e44 = z4.report_project_state()
# print("forth business factor future: ", e44)
#
# e = c.real_change_in_network(d, "K", "None")
# d.current_first_node = "K"
# d.current_second_node = "None"
# print("Attack From K to None")
# e = c.calculate_business_factor_with_state()
# print("real business factor: ", e)
# e1 = z1.report_current_state()
# print("first business factor: ", e1)
# e11 = z1.report_project_state()
# print("first business factor future: ", e11)
# e2 = z2.report_current_state()
# print("second business factor: ", e2)
# e22 = z2.report_project_state()
# print("second business factor future: ", e22)
# e3 = z3.report_current_state()
# print("third business factor: ", e3)
# e33 = z3.report_project_state()
# print("third business factor future: ", e33)
# e4 = z4.report_current_state()
# print("forth business factor: ", e4)
# e44 = z4.report_project_state()
# print("forth business factor future: ", e44)
