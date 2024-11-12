import glob
import os

import yaml
from tqdm import tqdm

from ClassModels.Attacker import Attacker
from ClassModels.BPMN import BPMN
from ClassModels.DataConvertor import DataConvertor
from ClassModels.MongoHelper import MongoHelper
from ClassModels.NetworkState import NetworkState


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

mongo_helper = MongoHelper()
jsons = import_yml_files_to_json()

for i in tqdm(range(len(jsons))):
    one_json = jsons[i]
    bpmn, network, attacker = initialize_elements(one_json)
    DataConvertor.create_model_csv(bpmn, network, attacker, one_json["DirectoryPath"])
    DataConvertor.create_result_csv(one_json["DirectoryPath"], one_json["ModelNumber"], mongo_helper)
    DataConvertor.create_graph(one_json["DirectoryPath"], one_json["ModelNumber"], bpmn, network, attacker)
    DataConvertor.create_sub_attack_path_graph(one_json["DirectoryPath"], one_json["ModelNumber"], attacker)
    DataConvertor.create_table_pictures(one_json["DirectoryPath"])

DataConvertor.create_table_of_all(jsons, 4)
    #DataConvertor.create_graph_from_file(one_json["DirectoryPath"])