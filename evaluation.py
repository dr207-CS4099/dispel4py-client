# read in the csv, convert to PEs, upload then run senti test on alternative

# for upload
from dispel4py.core import GenericPE
from client import d4pClient
import inspect 
from dispel4py.utils import *
from Aroma.data import *
from Aroma.similar import *
from deep_learn_search import *
# for cleaning
import pandas as pd
from ConvertToPE import ConvertToPE
from datasets import load_dataset

import pandas as pd
import json
import math


# upload several PEs
# keep one as the lookup, use this to look for all of the possible results
# see how many of these we can find
def createSimilarPEData(outputFile):


    ds = load_dataset("code_search_net", "python", trust_remote_code=True)
    print(ds)
    matching = {}
    lookupPEs = [] # used to search for the uploaded pe pair
    uploadPEs = set() # link id to the upload pe
    searchPEs = {}
    numFound = 0

    # if matching an existing, add the original to the search file (if not already there) use a set maybe
    # then store the matched function so that we can write it to a file
    for input in ds['test']:
        if input['func_documentation_string'] in matching:
            try:
                pe1 = ConvertToPE(matching[input['func_documentation_string']][0], False, matching[input['func_documentation_string']][1])

                # not necessary for pe2, as this will not be uploaded, and is used to target pe1
                pe2 = ConvertToPE(input['whole_func_string'], False, numFound)
            # TODO what is causing this?
            except:
                continue
            if pe1.pe == None or pe2.pe == None:
                continue

            if pe1.className in searchPEs:
                searchPEs[pe1.className]['relatedPEs'].append(pe2.className)

            else:
                searchPEs[pe1.className] = {'pe1' : matching[input['func_documentation_string']][0],
                                            'relatedPEs' :[pe2.className],
                                            'desc' : input['func_documentation_string']
                                            }
            numFound += 1
            uploadPEs.add(pe2.pe)

            
        else:
            matching[input['func_documentation_string']] = [input['whole_func_string'], len(matching)]            


    print(searchPEs)
    writePEToPYFile(uploadPEs)
    with open(outputFile, 'w', encoding='utf-8') as f:
        json.dump(searchPEs, f, ensure_ascii=False, indent=4)




# creates the other way around
# will delete soon
# def createSimilarPEDataOld(outputFile):
    
#     ds = load_dataset("code_search_net", "python", trust_remote_code=True)
#     print(ds)
#     matching = {}
#     lookupPEs = [] # used to search for the uploaded pe pair
#     uploadPEs = set() # link id to the upload pe

    
#     # need unique id for the name, use the unique id in both,
#     # ensure that equivalent pes are not uploaded twice (somehow need to check for equivalence?)
#     for input in ds['test']:
        
#         if input['func_documentation_string'] in matching:
#             print(matching[input['func_documentation_string']][1])
#             # convert to pes
#             try:
#                 # use the id value (from (len(matching) at the time of insertion) as a unique identifier for this function
#                 # as there may be two functions (ie get_object()) that are not similar but share the same name
#                 # and we want to be able to distinguish them without restricting our corpus size
#                 pe1 = ConvertToPE(matching[input['func_documentation_string']][0], False, matching[input['func_documentation_string']][1])

#                 # not necessary for pe2, as this will not be uploaded, and is used to target pe1
#                 pe2 = ConvertToPE(input['whole_func_string'], False)
#             # TODO what is causing this?
#             except:
#                 continue
#             if pe1.pe == None or pe2.pe == None:
#                 continue

#             # write pe2.pe to the upload pes
#             # only
#             if pe1.className in searchPEs:
#                 searchPEs[pe1.className]['relatedPEs'].append(pe2.className)
#             else:
#                 searchPEs[pe1.className] = {'pe1' : pe1.pe,
#                                             'relatedPEs' :[pe2.className],
#                                             'desc' : input['func_documentation_string']
#                                             }
#             temp = {'pe1' : pe1.className,
#                     'pe2' : input['whole_func_string'],
#                     'desc' : input['func_documentation_string']}
#             lookupPEs.append(temp)        
#             uploadPEs.add(pe1.pe)

#         else:
#             # print("failed")
#             matching[input['func_documentation_string']] = [input['whole_func_string'], len(matching)]


#     # create 
#     print("created: " + str(len(lookupPEs)) + " code pairs")

#     writePEToPYFile(uploadPEs)
#     with open(outputFile, 'w', encoding='utf-8') as f:
#         json.dump(lookupPEs, f, ensure_ascii=False, indent=4)


def writePEToPYFile(data):
    # need to be able to write the upload example to a file
    # store it's name, with pe2 in the data.json
    # so that we can get from one to the other
    with open("./Aroma/data.py", "w") as file:
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
def runSentimentAnalysis(dataFile):
    client = d4pClient()
    client.register("TestCorpus","TestCorpus")
    client.login("TestCorpus","TestCorpus")

    # iterates through each test set in the data file
    # checks if the expected pe is found
    with open(dataFile , "r") as file:
        file = json.load(file)

        
        

        dropAmounts = [0, 0.25, 0.5, 0.75, 0.9]

        
        set_global_min_pruned_score(0.3)
        set_global_min_similarity_score(0.25)
        with open("outputAdditional.csv", "w") as csvFile:
            csvFile.write("foundAroma,foundUnixcoder,potential,unrelatedAroma,unrelatedUnixcoder,dropAmount,im\n")
            for dropAmount in dropAmounts:
                for similarity in range(1,10):
                    
                    foundAroma = 0
                    unrelatedAroma = 0
                    potential= 0
                    
                    foundUnixcoder = 0
                    unrelatedUnixcoder = 0
                    sim = similarity * 0.1

                    set_similarity_cutoff(sim)
                    set_global_min_pruned_score(sim)
                    set_global_min_similarity_score(sim)
                    i = 0
                    for name, pePair in file.items():

                        i += 1
                        if i == 10:
                            break
                        # print("expecting: " + pePair['pe1'])
                        formatted = pePair['pe1'].splitlines()

                        # drop last n% of the search query
                        # TODO also use the version that is in the db?
                        # floor division
                        header = formatted[0]
                        formatted.pop()
                        cutSize = math.ceil(len(formatted) * dropAmount)
                        print(cutSize)
                        cutPE = "\n".join(formatted[cutSize:])
                        cutPE = header + "\n" + cutPE
                        print(header)
                        print(cutPE)

                        
                        unixcoder, aroma = client.search_Registry(cutPE, "pe", "code")
                        print(unixcoder)
                        compare = set(pePair['relatedPEs'])
                        potential += len(compare)
                        print(aroma)
                        print(unixcoder)
                        print(compare)

                        # TODO compare previous version, why is this not brilliant?
                        for pe in aroma:
                            if pe.lower() in compare:
                                foundAroma += 1 
                            else:
                                unrelatedAroma += 1

                        for pe in unixcoder:
                            if pe.lower() in compare:
                                foundUnixcoder += 1 
                            else:
                                unrelatedUnixcoder += 1
                    csvFile.write(f"{foundAroma}, {foundUnixcoder}, {potential}, {unrelatedAroma}, {unrelatedUnixcoder}, {dropAmount}, {sim}\n")
                    print("Aroma found " + str(foundAroma) + " of " + str(potential) + " and recalled unrelated: " + str(unrelatedAroma))
                    print("UnixCoder found " + str(foundUnixcoder) + " of " + str(potential) + " and recalled unrelated: " + str(unrelatedUnixcoder))   

#     client.search_Registry('''def get_conn(self):
#         """Returns a connection object"""
#         db = self.get_connection(self.presto_conn_id)
#         reqkwargs = None
#         if db.password is not None:
#             reqkwargs = {'auth': HTTPBasicAuth(db.login, db.password)}
#         return presto.connect(
#             host=db.host,
#             port=db.port,
#             username=db.login,
#             source=db.extra_dejson.get('source', 'airflow'),
#             protocol=db.extra_dejson.get('protocol', 'http'),
#             catalog=db.extra_dejson.get('catalog', 'hive'),
#             requests_kwargs=reqkwargs,
#             schema=db.schema)''', "pe", "code")
    
#     client.search_Registry('''def _process(self):
#             """Returns a connection object
#             """
#             db = self.get_connection(getattr(self, self.conn_name_attr))
#             return self.connector.connect(
#                 host=db.host,
#                 port=db.port,
#                 username=db.login,
#                 schema=db.schema)
# ''', "pe", "code")
    

#     client.search_Registry('''def _process(self):\n            \"\"\"\n            Default filters for model\n            \"\"\"\n            return (\n                super().get_count_query()\n                .filter(models.DagModel.is_active)\n                .filter(~models.DagModel.is_subdag)\n            )"'''
#                            , "pe", "code")
dataFile = "./Aroma/data.json"
# createSimilarPEData(dataFile)

# uploadPEData('Aroma.data')

runSentimentAnalysis(dataFile)