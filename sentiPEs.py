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
client = d4pClient()
client.register("root","root")
client.login("root","root")

client2 = d4pClient()
client2.register("noDesc","noDesc")
client2.login("noDesc","noDesc")
# print("\n Text to Code Search \n")
# client.search_Registry("prime","pe","text")

print("\n Code to Text Search \n")
# client.search_Registry("random.randint(1, 1000)","pe","code")
# client.search_Registry("","pe","code")

# client.search_Registry("prime","pe","text")
# client.search_Registry("PE to perform sentiment analysis on a text","pe","text")
# # client2.search_Registry("PE to perform sentiment analysis on a text","pe","text")

# #RandomwordProducer
# client.search_Registry("PE to produce a random word", "pe", "text")
# client2.search_Registry("agios", "pe", "text")
# client2.search_Registry("""

#     def process(self, inputs=None):
#         word = random.choice(RandomWordProducer.words)
#         outputs = {"output": [word]}
#         return outputs")
#     """, "pe", "code")
# # should this not be higher?
# client.search_Registry("This PE produces a random word as an output.", "pe", "text")
# client2.search_Registry("This PE produces a random word as an output.", "pe", "text")

# client2.search_Registry("check for prime input", "pe", "text")

# #WordCounter
# client2.search_Registry(" self.mywords[word] += 1", "pe", "code")



# client2.search_Registry('''
#     class c:
#         def test():
#             for line in afinnfile:
#                 term, score = line.split(
#                     "\t"
#                 )''', "pe", "code")

client2.search_Registry('''class c:
        def test():
            GenericPE.__init__(self)
            self._add_input("input", grouping=[2, 3])
            self._add_output("output")
            self.mood = {}
            self.happiest = None, -5000''', "pe", "code")

client2.search_Registry('''class c:
    def _process(self, data):
        # print("AFINNSentimeScore %s %s %s" % (article, str(avg_score),self.method))
        return (article, avg_score, self.method)''', "pe", "code")
# Why is the user id set to max pe_id += 1
# Surely it should be PE independent and actually check the description updates
# likewise, if the code is updated it should update itself aswell
# surely that is trivial - generate pe_code and compare
# yes performance overhead, but otherwise will make updating a nightmare