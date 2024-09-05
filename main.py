import json
import yaml
from ClassModels.BPMN import BPMN
from ClassModels.NetworkState import NetworkState
from ClassModels.Attacker import Attacker
from pprint import pprint

with open('BPMN-Network-Model/Model1/model1.yml', 'r') as file:
    configuration = yaml.safe_load(file)

with open('config.json', 'w') as json_file:
    json.dump(configuration, json_file)

output = json.dumps(json.load(open('config.json')), indent=2)
print(output)

a = json.load(open('config.json'))
b = BPMN(a["BPMN"])
c = NetworkState(a["Network"])
d = Attacker(a["Attack"])

b.calculate_business_importance()
b.calculate_process_priority()

c.add_host_importance(b)

# pprint(b.resource_pools)
# pprint(b.processes)
# pprint(b.workflow_paths)
# pprint(b.missions)

#e = d.get_success_attack_node("A")
#f = d.get_failure_attack_node("A")
#g = d.get_host_related_security_factor("A", c.hosts_configuration)
#h = d.is_attack_successful("A", g)
#i = d.create_attack_path("A", c.hosts_configuration, [])

#d.create_numbers_of_attack_path("A", c.hosts_configuration, 10000)
#pprint(d.attack_path_list_object)

e = c.real_change_in_network(d, "A", "B")
print("Attack From A to B")
e = c.calculate_business_factor_with_state()
pprint(e)

e = c.real_change_in_network(d, "B", "C")
print("Attack From B to C")
e = c.calculate_business_factor_with_state()
pprint(e)

e = c.real_change_in_network(d, "C", "D")
print("Attack From C to D")
e = c.calculate_business_factor_with_state()
pprint(e)

