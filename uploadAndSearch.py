from dispel4py.core import GenericPE
from client import d4pClient
import inspect 
from dispel4py.utils import *

import sys, inspect

from sample import *
# from testPEs import Avail_locations
from test_PEs.examples.graph_testing.testing_PEs import *
# doesn't work due to the length of the encoding 
from test_PEs.examples.article_sentiment_analysis.analysis_sentiment_partition import *
from testPEs import *

pe_ignores = ['ConsumerPE', 'IterativePE', 'GenericPE', 'ProducerPE',
              'AFINNSentimeScore', 'SentiWordNetScore', 'SentiSynset']
modules = ['sample', 'test_PEs.examples.graph_testing.testing_PEs', 'test_PEs.examples.article_sentiment_analysis.analysis_sentiment_partition']

classes = []
for module in modules:
    classes.append([[cls_name, cls_obj] for cls_name, cls_obj in inspect.getmembers(sys.modules[module]) if inspect.isclass(cls_obj) and not cls_name in pe_ignores and issubclass(cls_obj, GenericPE)])
        
     

client2 = d4pClient()
print("\n Create User and Login \n")
client2.register("noDesc","noDesc")
client2.login("noDesc","noDesc")

client2.register_PE(SentiWordNetScore("SentiWordNet_3.0.0_20130122.txt"))
client2.register_PE(AFINNSentimeScore("AFINN-111.txt"))
# client.register_PE(SentiSynset(), 'SentiSynset')
# client2.register_PE(Avail_locations())
# note that this only works for constructors without any parameter
for module_classes in classes:
    for cls_name, cls_obj in module_classes:
        print(cls_name)
        try:
            client2.register_PE(cls_obj())
        except:
            print("Warning, failed to upload: likely due to unrecognised characters")
        
        
        