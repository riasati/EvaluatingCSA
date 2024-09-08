import pymongo


class MongoHelper:
    def __init__(self):
        self.client = pymongo.MongoClient("mongodb://localhost:27017/")
        self.db = self.client["csa_evaluating"]
        self.collection = self.db["csa_evaluating"]
        self.model_number = None

    def add_model_number(self, model_number):
        self.model_number = model_number

    def add_one_record(self, record: dict):
        record["ModelNumber"] = self.model_number
        self.collection.insert_one(record)

    def find_all_record_of_model(self):
        myquery = {"ModelNumber": self.model_number}
        return list(self.collection.find(myquery))

    def find_record_from_another(self, record):
        myquery = {"ModelNumber": self.model_number, "AttackPath": record["AttackPath"],
                   "AttackPathNumber": record["AttackPathNumber"], "FirstNode": record["SecondNode"]}
        return self.collection.find_one(myquery)

    def delete_all_records(self):
        self.collection.delete_many({})

    def delete_all_records_of_model(self):
        self.collection.delete_many({"ModelNumber": self.model_number})
