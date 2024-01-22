from dispel4py.core import GenericPE
from client import d4pClient
import inspect 
from dispel4py.utils import *
from CLIENT_EXAMPLES.AstroPhysics import *

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



client2 = d4pClient()
print("\n Create User and Login \n")
client2.register("testUser","testUser")
client2.login("testUser","testUser")


# register pes
client2.register_PE(read)
client2.register_PE(votab)
client2.register_PE(filt)
client2.register_PE(intext)
#register workflow
client2.register_Workflow(graph, "Astrophysics", "A workflow to compute the internal extinction of galaxies")