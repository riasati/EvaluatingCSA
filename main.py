import json
import yaml
from ClassModels.BPMN import BPMN
from ClassModels.NetworkState import NetworkState

# with open('BPMN-Network-Model/Model1/model1.yml', 'r') as file:
#     configuration = yaml.safe_load(file)
#
# with open('config.json', 'w') as json_file:
#     json.dump(configuration, json_file)
#
# output = json.dumps(json.load(open('config.json')), indent=2)
# print(output)

a = json.load(open('config.json'))
b = BPMN(a["BPMN"])
c = NetworkState(a["Network"])

d = c.change_name_of_subnet("Subnet3")
e = c.access_of_one_subnet(2)
f = c.access_of_one_subnet_to_another(3,4)
print(f)