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



# run sentiment analysis on the text search
def runSentimentAnalysis(dataFile):
    client = d4pClient()
    client.register("TestCorpusDesc2","TestCorpusDesc2")
    client.login("TestCorpusDesc2","TestCorpusDesc2")

    # iterates through each test set in the data file
    # checks if the expected pe is found
    with open(dataFile , "r") as file:
        file = json.load(file)
        
        
        
        with open("outputText.csv", "w") as csvFile:
            csvFile.write("foundUnixcoder,potential,unrelatedUnixcoder,dropAmount,sim\n")

            for similarity in range(1,10):
                potential= 0
                
                foundUnixcoder = 0
                unrelatedUnixcoder = 0
                sim = similarity * 0.1

                set_similarity_cutoff(sim)

                i=0
                for name, pePair in file.items():

                    # i += 1
                    # if i == 10:
                    #     break
                    # print("expecting: " + pePair['pe1'])
                    

                    
                    unixcoder= client.search_Registry(pePair['desc'], "pe", "text")
                    print(unixcoder)
                    compare = set(pePair['relatedPEs'])
                    potential += len(compare)
                    # print(aroma)
                    # print(unixcoder)
                    # print(compare)
                    for pe in unixcoder:
                        if pe.lower() in compare:
                            foundUnixcoder += 1 
                        else:
                            unrelatedUnixcoder += 1
                csvFile.write(f"{foundUnixcoder}, {potential}, {unrelatedUnixcoder}, {sim}\n")
                print("UnixCoder found " + str(foundUnixcoder) + " of " + str(potential) + " and recalled unrelated: " + str(unrelatedUnixcoder))   


dataFile = "./Aroma/data.json"

runSentimentAnalysis(dataFile)