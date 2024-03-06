# run uploadExamples first to ensure that the PEs are uploaded

# Imports 
from dispel4py.base import ProducerPE, IterativePE, ConsumerPE
from dispel4py.workflow_graph import WorkflowGraph
import random
from easydict import EasyDict as edict
from client import d4pClient,Process
import inspect 
from dispel4py.utils import *


client2 = d4pClient()
client2.register("testUser","testUser")
client2.login("testUser","testUser")


# client2.search_Registry('''
#     def _process():
#         import requests
#         count, ra, dec, sr = data
#         print('reading VOTable RA=%s, DEC=%s' % (ra,dec))
#         url = 'http://vizier.u-strasbg.fr/viz-bin/votable/-A?-source=VII/237&RA=%s&DEC=%s&SR=%s' % (ra, dec, sr)
#         response = requests.get(url)
#         return [count, ra, dec, response.text]''', "workflow", "code")
# client2.search_Registry("Astrophysics", "workflow", "code")
# client2.search_Registry('''class c:
#         def test():
#             GenericPE.__init__(self)
#             self._add_input("input", grouping=[2, 3])
#             self._add_output("output")
#             self.mood = {}
#             self.happiest = None, -5000''', "pe", "code")

client2.search_Registry("astrophysics workflow", "workflow", "text")