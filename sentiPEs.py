# run uploadExamples first to ensure that the PEs are uploaded

# Imports 
from dispel4py.base import ProducerPE, IterativePE, ConsumerPE
from dispel4py.workflow_graph import WorkflowGraph
import random
from easydict import EasyDict as edict
from client import d4pClient,Process
import inspect 
from dispel4py.utils import *



#Create User and Login 
print("\n Create User and Login \n")

client2 = d4pClient()
client2.register("noDesc","noDesc")
client2.login("noDesc","noDesc")

# #RandomwordProducer
# client2.search_Registry("agios", "pe", "text")
# client2.search_Registry("""

#     def process(self, inputs=None):
#         word = random.choice(RandomWordProducer.words)
#         outputs = {"output": [word]}
#         return outputs")
#     """, "pe", "code")
# should this not be higher?
# client.search_Registry("This PE produces a random word as an output.", "pe", "text")
# client2.search_Registry("This PE produces a random word as an output.", "pe", "text")

# client2.search_Registry("check for prime input", "pe", "text")

# #WordCounter
# client2.search_Registry(" self.mywords[word] += 1", "pe", "code")



# client2.search_Registry('''
# for line in afinnfile:
#     term, score = line.split(
#         "\t"
#     )''', "pe", "code")



# client2.search_Registry('''
# def _process(self,data):
#     # check that we have recognised any words, then find a median of the score
#     if count == 0:
#             avg = sent
#     else:
#         avg = sent / count
                
#     return (article, avg_score, self.method)''', "pe", "code")
# class BASE64_b64decode
# client2.search_Registry('''class c:
# def test():
#     try:
#         decoder()
#     except UnicodeDecodeError:
#         return decoded''', "pe", "code")
#API config
# client2.search_Registry('''class c:
#     def test():
#         opts.update({
#             'log_file': opts.get('api_log', DEFAULT_API_OPTS['api_log']),
#             'pid': opts.get('api_pid', DEFAULT_API_OPTS['api_pid']),
            
#         })

#         prepend_root_dir(opts, [
#             'api_pid',
#             'api_log',
#             'log',
#             'pid'
#         ])
#         return opts''', "pe", "code")

# This file contains a selection of example PE searches based on the PEs in testPEs
# these were generated from a subsection of codeSearchNet python functions
# if running this on a new system, you will need to run uploadExamples.py first



client2.search_Registry('''class c:
        def example(self):
            return true
        def test():
            GenericPE.__init__(self)
            self.mood = {}
            self.happiest = None, -5000''', "pe", "code")