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

# #RandomwordProducer
client.search_Registry("PE to produce a random word", "pe", "text")
client2.search_Registry("agios", "pe", "text")
client2.search_Registry("""

    def process(self, inputs=None):
        word = random.choice(RandomWordProducer.words)
        outputs = {"output": [word]}
        return outputs")
    """, "pe", "code")
# should this not be higher?
client.search_Registry("This PE produces a random word as an output.", "pe", "text")
client2.search_Registry("This PE produces a random word as an output.", "pe", "text")

client2.search_Registry("check for prime input", "pe", "text")

#WordCounter
client2.search_Registry(" self.mywords[word] += 1", "pe", "code")



client2.search_Registry('''
    class c:
        def test():
            for line in afinnfile:
                term, score = line.split(
                    "\t"
                )''', "pe", "code")

client2.search_Registry('''class c:
        def test():
            GenericPE.__init__(self)
            self._add_input("input", grouping=[2, 3])
            self._add_output("output")
            self.mood = {}
            self.happiest = None, -5000''', "pe", "code")

client2.search_Registry('''class c:
    def _process(self, data):
         # check that we have recognised any words, then find a median of the score
        if count == 0:
                avg = sent
        else:
            avg = sent / count
                        
        return (article, avg_score, self.method)''', "pe", "code")
# class BASE64_b64decode
client2.search_Registry('''class c:
def test():
    try:
        decoder()
    except UnicodeDecodeError:
        return decoded''', "pe", "code")
#API config
client2.search_Registry('''class c:
    def test():
        opts.update({
            'log_file': opts.get('api_log', DEFAULT_API_OPTS['api_log']),
            'pid': opts.get('api_pid', DEFAULT_API_OPTS['api_pid']),
            
        })

        prepend_root_dir(opts, [
            'api_pid',
            'api_log',
            'log',
            'pid'
        ])
        return opts''', "pe", "code")

# client.register("TestCorpus","TestCorpus")
# client.login("TestCorpus","TestCorpus")

# client.search_Registry('''class Get_conn(ProducerPE):\n    def _process(self):\n            \"\"\"Returns a connection object\n            \"\"\"\n            db = self.get_connection(getattr(self, self.conn_name_attr))\n            return self.connector.connect(\n                host=db.host,\n                port=db.port,\n                username=db.login,\n                schema=db.schema)''', "pe", "code")