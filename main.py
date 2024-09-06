import json
import yaml
from ClassModels.BPMN import BPMN
from ClassModels.CSASimulator import CSA
from ClassModels.NetworkState import NetworkState
from ClassModels.Attacker import Attacker
from pprint import pprint

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
d = Attacker(a["Attack"])



z1 = CSA(d, c, 0.5, [50, 50, 50, 50], False)
z2 = CSA(d, c, 0.7, [50, 50, 50, 50], False)
z3 = CSA(d, c, 0.9, [50, 50, 50, 50], False)
z4 = CSA(d, c, 0.5, [50, 50, 50, 50], True)

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

d.create_numbers_of_attack_path("A", c.hosts_configuration, 10000)
#pprint(d.attack_path_list_object)
print(d.attack_path_list_object.keys())
#d.fill_current_attack_path(list(d.attack_path_list_object.keys())[1])
d.fill_current_attack_path('["A", "C", "E", "G", "I", "K", "None"]')

e = c.real_change_in_network(d, "A", "C")
d.current_first_node = "A"
d.current_second_node = "C"
print("Attack From A to C")
e = c.calculate_business_factor_with_state()
e1 = z1.report_current_state()
e11 = z1.report_project_state()
e2 = z2.report_current_state()
e22 = z2.report_project_state()
e3 = z3.report_current_state()
e33 = z3.report_project_state()
e4 = z4.report_current_state()
e44 = z4.report_project_state()
print("real business factor: ", e)
print("first business factor: ", e1)
print("first business factor future: ", e11)
print("second business factor: ", e2)
print("second business factor future: ", e22)
print("third business factor: ", e3)
print("third business factor future: ", e33)
print("forth business factor: ", e4)
print("forth business factor future: ", e44)

e = c.real_change_in_network(d, "C", "E")
d.current_first_node = "C"
d.current_second_node = "E"
print("Attack From C to E")
e = c.calculate_business_factor_with_state()
e1 = z1.report_current_state()
e11 = z1.report_project_state()
e2 = z2.report_current_state()
e22 = z2.report_project_state()
e3 = z3.report_current_state()
e33 = z3.report_project_state()
e4 = z4.report_current_state()
e44 = z4.report_project_state()
print("real business factor: ", e)
print("first business factor: ", e1)
print("first business factor future: ", e11)
print("second business factor: ", e2)
print("second business factor future: ", e22)
print("third business factor: ", e3)
print("third business factor future: ", e33)
print("forth business factor: ", e4)
print("forth business factor future: ", e44)

e = c.real_change_in_network(d, "E", "G")
d.current_first_node = "E"
d.current_second_node = "G"
print("Attack From E to G")
e = c.calculate_business_factor_with_state()
e1 = z1.report_current_state()
e11 = z1.report_project_state()
e2 = z2.report_current_state()
e22 = z2.report_project_state()
e3 = z3.report_current_state()
e33 = z3.report_project_state()
e4 = z4.report_current_state()
e44 = z4.report_project_state()
print("real business factor: ", e)
print("first business factor: ", e1)
print("first business factor future: ", e11)
print("second business factor: ", e2)
print("second business factor future: ", e22)
print("third business factor: ", e3)
print("third business factor future: ", e33)
print("forth business factor: ", e4)
print("forth business factor future: ", e44)

e = c.real_change_in_network(d, "G", "I")
d.current_first_node = "G"
d.current_second_node = "I"
print("Attack From G to I")
e = c.calculate_business_factor_with_state()
e1 = z1.report_current_state()
e11 = z1.report_project_state()
e2 = z2.report_current_state()
e22 = z2.report_project_state()
e3 = z3.report_current_state()
e33 = z3.report_project_state()
e4 = z4.report_current_state()
e44 = z4.report_project_state()
print("real business factor: ", e)
print("first business factor: ", e1)
print("first business factor future: ", e11)
print("second business factor: ", e2)
print("second business factor future: ", e22)
print("third business factor: ", e3)
print("third business factor future: ", e33)
print("forth business factor: ", e4)
print("forth business factor future: ", e44)

e = c.real_change_in_network(d, "I", "K")
d.current_first_node = "I"
d.current_second_node = "K"
print("Attack From I to K")
e = c.calculate_business_factor_with_state()
e1 = z1.report_current_state()
e11 = z1.report_project_state()
e2 = z2.report_current_state()
e22 = z2.report_project_state()
e3 = z3.report_current_state()
e33 = z3.report_project_state()
e4 = z4.report_current_state()
e44 = z4.report_project_state()
print("real business factor: ", e)
print("first business factor: ", e1)
print("first business factor future: ", e11)
print("second business factor: ", e2)
print("second business factor future: ", e22)
print("third business factor: ", e3)
print("third business factor future: ", e33)
print("forth business factor: ", e4)
print("forth business factor future: ", e44)

e = c.real_change_in_network(d, "K", "None")
d.current_first_node = "K"
d.current_second_node = "None"
print("Attack From K to None")
e = c.calculate_business_factor_with_state()
e1 = z1.report_current_state()
e11 = z1.report_project_state()
e2 = z2.report_current_state()
e22 = z2.report_project_state()
e3 = z3.report_current_state()
e33 = z3.report_project_state()
e4 = z4.report_current_state()
e44 = z4.report_project_state()
print("real business factor: ", e)
print("first business factor: ", e1)
print("first business factor future: ", e11)
print("second business factor: ", e2)
print("second business factor future: ", e22)
print("third business factor: ", e3)
print("third business factor future: ", e33)
print("forth business factor: ", e4)
print("forth business factor future: ", e44)

