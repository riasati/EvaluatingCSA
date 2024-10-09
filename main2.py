import glob
import os

import yaml

from ClassModels.Attacker import Attacker
from ClassModels.BPMN import BPMN
from ClassModels.DataConvertor import DataConvertor
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

def initialize_elements(one_json):
    bpmn = BPMN(one_json["BPMN"])
    network = NetworkState(one_json["Network"])
    attacker = Attacker(one_json["Attack"])

    network.add_host_importance(bpmn)
    return bpmn, network, attacker


jsons = import_yml_files_to_json()

for one_json in jsons:
    bpmn, network, attacker = initialize_elements(one_json)
    DataConvertor.create_model_csv(bpmn, network, attacker, one_json["DirectoryPath"])