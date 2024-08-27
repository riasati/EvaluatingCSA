import json
import yaml

with open('BPMN-Network-Model/Model1/model1.yml', 'r') as file:
    configuration = yaml.safe_load(file)

with open('config.json', 'w') as json_file:
    json.dump(configuration, json_file)

output = json.dumps(json.load(open('config.json')), indent=2)
print(output)