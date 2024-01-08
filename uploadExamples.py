# Imports
from dispel4py.core import GenericPE
from client import d4pClient
import inspect 
from dispel4py.utils import *

import sys, inspect

from sample import *
from test_PEs.examples.graph_testing.testing_PEs import *
# doesn't work due to the length of the encoding 
from test_PEs.examples.article_sentiment_analysis.analysis_sentiment_partition import *

# from test_PEs.examples.seismo.preprocess_example import * 
# from dispel4py.examples.seismo.simple_PEs import * 
# from dispel4py.examples.seismo.test_chain import * 

# print(clsmembers = inspect.getmembers(sys.modules["sample"], inspect.isclass))
# https://progr.interplanety.org/en/python-how-to-get-defined-classes-list-from-module-py-file/


# ignore the PE classes as we do not want to run anything on them
pe_ignores = ['ConsumerPE', 'IterativePE', 'GenericPE', 'ProducerPE',
              'AFINNSentimeScore', 'SentiWordNetScore', 'SentiSynset']
modules = ['sample', 'test_PEs.examples.graph_testing.testing_PEs', 'test_PEs.examples.article_sentiment_analysis.analysis_sentiment_partition'] #, 'test_PEs.examples.seismo.preprocess_example']
# print(sys.modules)
classes = []
for module in modules:
    classes.append([[cls_name, cls_obj] for cls_name, cls_obj in inspect.getmembers(sys.modules[module]) if inspect.isclass(cls_obj) and not cls_name in pe_ignores and issubclass(cls_obj, GenericPE)])


client2 = d4pClient()
print("\n Create User and Login \n")
client2.register("noDesc","noDesc")
client2.login("noDesc","noDesc")

client2.register_PE(AFINNSentimeScore("AFINN-111.txt"))
client2.register_PE(SentiWordNetScore("SentiWordNet_3.0.0_20130122.txt"))
# client.register_PE(SentiSynset(), 'SentiSynset')

# note that this only works for constructors without any parameter
for module_classes in classes:
    for cls_name, cls_obj in module_classes:
        print(cls_name)
        client2.register_PE(cls_obj())
        
        
        
        

# client = d4pClient()

# #Create User and Login 
# print("\n Create User and Login \n")
# client.register("root","root")
# client.login("root","root")

# client.register_PE(AFINNSentimeScore("AFINN-111.txt"), 'AFINNSentimeScoreFull')
# client.register_PE(SentiWordNetScore("SentiWordNet_3.0.0_20130122.txt"), 'SentiWordNetScore')
# # client.register_PE(SentiSynset(), 'SentiSynset')

# # note that this only works for constructors without any parameter
# for module_classes in classes:
#     for cls_name, cls_obj in module_classes:
#         print(cls_name)
#         client.register_PE(cls_obj(), cls_name)
        
        


        
        
