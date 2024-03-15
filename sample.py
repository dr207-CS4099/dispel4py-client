# Imports 
from dispel4py.base import ProducerPE, IterativePE, ConsumerPE
from dispel4py.workflow_graph import WorkflowGraph
import random
from easydict import EasyDict as edict
from client import d4pClient,Process
import inspect 
from dispel4py.utils import *

from dispel4py.utils import *
from CLIENT_EXAMPLES.AstroPhysics import *

class NumberProducer(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
        
    def _process(self, inputs):
        # this PE produces one input
        result= random.randint(1, 1000)
        return result

class IsPrime(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, num):
        # this PE consumes one input and produces one output
        print("before checking data - %s - is prime or not" % num)
        if all(num % i != 0 for i in range(2, num)):
            return num

class PrintPrime(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, num):
        # this PE consumes one input
        print("the num %s is prime" % num)

producer = NumberProducer()
isprime = IsPrime()
printprime = PrintPrime()

graph = WorkflowGraph()
graph.connect(producer, 'output', isprime, 'input')
graph.connect(isprime, 'output', printprime, 'input')

#Create Client Instance
print("\n Create Client Instance\n")
client = d4pClient()

#Create User and Login 
print("\n Create User and Login \n")
client.register("root","root")
client.login("root","root")

print("\n Register Graph \n")
client.register_Workflow(graph,"graph1")

# this originally did not consider what happens when there are no pes...
# the sample really should create one before running so that atleast it can run
client.register_PE(isprime, "IsPrime")
client.register_PE(printprime, "PrintPrime")
client.register_PE(producer, "NumberProducer")


print("\n Text to Code Search \n")
client.search_Registry("prime","pe","text")

print("\n Code to Text Search \n")
client.search_Registry('''class c:
    def _process(self, data):
        return random.randint(1, 1000)''',"pe","code")
# client.search_Registry("","pe","code")


print("\nRegistering Workflow\n")
graph = WorkflowGraph()
read = ReadRaDec()
read.name = 'read'
votab = GetVOTable()
filt = FilterColumns()
filt.columns = ['MType', 'logR25']
intext = InternalExtinction()

graph.connect(read, 'output', votab, 'input')
graph.connect(votab, 'output', filt, 'input')
graph.connect(filt, 'output', intext, 'input')




client.register_PE(read)
client.register_PE(votab)
client.register_PE(filt)
client.register_PE(intext)

#register workflow
client.register_Workflow(graph, "Astro_physics2")

print("\nWorkflow text-to-code search\n")
client.search_Registry("physics calculation", "workflow", "text")
# client.search_Registry("")

client.search_Registry('''class C:
                       def test(self, data):
        url = 'http://vizier.u-strasbg.fr/viz-bin/votable/-A?-source=VII/237&RA=%s&DEC=%s&SR=%s' % (ra, dec, sr)
        response = requests.get(url)
        return [count, ra, dec, response.text]''', "workflow", "code")
# client.run(graph,input=5)


# bug with this EOFError: Ran out of input
# print("\n Execute Workflow with Multi\n")
# client.run(graph,input=5,process=Process.MULTI,args={'num':5,'simple': False})



