# read in the csv, convert to PEs, upload then run senti test on alternative

# for upload
from dispel4py.core import GenericPE
from client import d4pClient
import inspect 
from dispel4py.utils import *
from data import *


# for cleaning
import pandas as pd
from ConvertToPE import ConvertToPE
from datasets import load_dataset

import pandas as pd
import json



def createSimilarPEData(outputFile):
    
    ds = load_dataset("code_search_net", "python", trust_remote_code=True)
    print(ds)
    matching = {}
    lookupPEs = [] # used to search for the uploaded pe pair
    uploadPEs = set() # link id to the upload pe

    # need unique id for the name, use the unique id in both,
    # ensure that equivalent pes are not uploaded twice (somehow need to check for equivalence?)
    for input in ds['test']:
        
        if input['func_documentation_string'] in matching:
            print(matching[input['func_documentation_string']][1])
            # convert to pes
            try:
                # use the id value (from (len(matching) at the time of insertion) as a unique identifier for this function
                # as there may be two functions (ie get_object()) that are not similar but share the same name
                # and we want to be able to distinguish them without restricting our corpus size
                pe1 = ConvertToPE(matching[input['func_documentation_string']][0], False, matching[input['func_documentation_string']][1])

                # not necessary for pe2, as this will not be uploaded, and is used to target pe1
                pe2 = ConvertToPE(input['whole_func_string'], False)
            # TODO what is causing this?
            except:
                continue
            if pe1.pe == None or pe2.pe == None:
                continue
                                

            temp = {'pe1' : pe1.className,
                    'pe2' : input['whole_func_string'],
                    'desc' : input['func_documentation_string']}
            lookupPEs.append(temp)        
            uploadPEs.add(pe1.pe)

        else:
            # print("failed")
            matching[input['func_documentation_string']] = [input['whole_func_string'], len(matching)]


    # create 
    print("created: " + str(len(lookupPEs)) + " code pairs")

    writePEToPYFile(uploadPEs)
    with open(outputFile, 'w', encoding='utf-8') as f:
        json.dump(lookupPEs, f, ensure_ascii=False, indent=4)


def writePEToPYFile(data):
    # need to be able to write the upload example to a file
    # store it's name, with pe2 in the data.json
    # so that we can get from one to the other
    with open("data.py", "w") as file:
        file.write("from dispel4py.core import GenericPE\nfrom dispel4py.base import IterativePE, ConsumerPE, ProducerPE\n")
        for pe in data:
            file.write(pe + "\n")


# function to upload data from the file to the database
# technically we don't need the file, but we can just 
def uploadPEData(inputFile):
    client = d4pClient()
    print("\n Create User and Login \n")
    client.register("TestCorpus","TestCorpus")
    client.login("TestCorpus","TestCorpus")

    print(inspect.getmembers(sys.modules[inputFile]))
    classes = [[cls_name, cls_obj] for cls_name, cls_obj in inspect.getmembers(sys.modules[inputFile]) if inspect.isclass(cls_obj) and issubclass(cls_obj, GenericPE)]
    print(len(classes))
    for cls_name, cls_obj in classes:
        print(cls_name)
        try:
            client.register_PE(cls_obj())
        except:
            print("Warning, failed to upload: likely due to unrecognised characters")
        

# function to run sentiment analysis
# should take the 
def runSentimentAnalysis():
    client = d4pClient()
    client.register("TestCorpus","TestCorpus")
    client.login("TestCorpus","TestCorpus")

    # iterates through each test set in the data file
    # checks if the expected pe is found
    with open("data.json", "r") as file:
        file = json.load(file)
        for pePair in file:
            print("expecting: " + pePair['pe1'])
            client.search_Registry(pePair['pe2'], "pe", "code")
            
#     client.search_Registry('''def _process(self):
#             """
#             Default filters for model
#             """
#             return (
#                 super().get_query()
#                 .filter(or_(models.DagModel.is_active,
#                             models.DagModel.is_paused))
#                 .filter(~models.DagModel.is_subdag)
#             )''', "pe", "code")
    
#     client.search_Registry('''def _process(self):
#             """
#             Default filters for model
#             """
#             return (
#                 super().get_count_query()
#                 .filter(models.DagModel.is_active)
#                 .filter(~models.DagModel.is_subdag)
#             )
# ''', "pe", "code")
    

#     client.search_Registry('''def _process(self):\n            \"\"\"\n            Default filters for model\n            \"\"\"\n            return (\n                super().get_count_query()\n                .filter(models.DagModel.is_active)\n                .filter(~models.DagModel.is_subdag)\n            )"'''
#                            , "pe", "code")
dataFile = "data.json"
# createSimilarPEData(dataFile)

# uploadPEData('data')

runSentimentAnalysis()