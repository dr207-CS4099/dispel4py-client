from dispel4py.core import GenericPE
from client import d4pClient
import inspect 
from dispel4py.utils import *
from CLIENT_EXAMPLES.AstroPhysics import *



class GetVOTable2(IterativePE):
    
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, data):
        import requests
        count, ra, dec, sr = data
        print('reading VOTable RA=%s, DEC=%s' % (ra,dec))
        url = 'http://vizier.u-strasbg.fr/viz-bin/votable/-A?-source=VII/237&RA=%s&DEC=%s&SR=%s' % (ra, dec, sr)
        response = requests.get(url)
        return [count, ra, dec, response.text]





graph = WorkflowGraph()
read = ReadRaDec()
read.name = 'read'
votab = GetVOTable()
votab2 = GetVOTable2()
filt = FilterColumns()
filt.columns = ['MType', 'logR25']
intext = InternalExtinction()

graph.connect(read, 'output', votab, 'input')
graph.connect(votab, 'output', filt, 'input')
graph.connect(filt, 'output', intext, 'input')



client2 = d4pClient()
print("\n Create User and Login \n")
client2.register("testUser","testUser")
client2.login("testUser","testUser")


# register pes
client2.register_PE(read)
client2.register_PE(votab)
client2.register_PE(votab2)
client2.register_PE(filt)
client2.register_PE(intext)

#register workflow
client2.register_Workflow(graph, "Astro_physics2")