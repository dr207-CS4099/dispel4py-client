# evaluation of workflows with text-to-code and code-to-code search


from dispel4py.core import GenericPE
from client import d4pClient
import inspect 
from dispel4py.utils import *
from CLIENT_EXAMPLES.AstroPhysics import *
from CLIENT_EXAMPLES.cleanString import *
from CLIENT_EXAMPLES.containsB import *
from CLIENT_EXAMPLES.IsPrime import *
from CLIENT_EXAMPLES.maxValueHasFactor import *
from CLIENT_EXAMPLES.WordCount import *



def add_workflows():
    # astrophysics workflow
    astro = WorkflowGraph()
    read = ReadRaDec()
    read.name = 'read'
    votab = GetVOTable()
    filt = FilterColumns()
    filt.columns = ['MType', 'logR25']
    intext = InternalExtinction()

    astro.connect(read, 'output', votab, 'input')
    astro.connect(votab, 'output', filt, 'input')
    astro.connect(filt, 'output', intext, 'input')




    # register pes
    client.register_PE(read)
    client.register_PE(votab)
    client.register_PE(filt)
    client.register_PE(intext)

    #register workflow
    client.register_Workflow(astro, "Astro_physics")


    # clean string workflow

    cleanString = WorkflowGraph()
    inputString = InputString()
    removePunctuation = RemovePunctuation()
    wordsToLower = WordsToLower()
    splitOnSpaces = SplitOnSpaces()
    printString = PrintString()


    client.register_PE(inputString)
    client.register_PE(removePunctuation)
    client.register_PE(wordsToLower)
    client.register_PE(splitOnSpaces)
    client.register_PE(printString)


    cleanString.connect(inputString, 'output', removePunctuation, 'input')
    cleanString.connect(removePunctuation, 'output', wordsToLower, 'input')
    cleanString.connect(wordsToLower, 'output', splitOnSpaces, 'input')
    cleanString.connect(splitOnSpaces, 'output', printString, 'input')


    client.register_Workflow(cleanString, 'Clean_string')

    # contains B workflow
    containsBGraph = WorkflowGraph()
    initialString = InitialString()
    toLower = ToLower()
    containsB = ContainsB()

    containsBGraph.connect(initialString, 'output', toLower, 'input')
    containsBGraph.connect(toLower, 'output', containsB, 'input')

    client.register_Workflow(containsBGraph, 'Contains_B')


    #isPrime workflow
    producer = NumberProducer()
    isprime = IsPrime()
    printprime = PrintPrime()

    isPrimeGraph = WorkflowGraph()
    isPrimeGraph.connect(producer, 'output', isprime, 'input')
    isPrimeGraph.connect(isprime, 'output', printprime, 'input')


    client.register_Workflow(isPrimeGraph, 'Is_prime')


    # maxValueHasFactor workflow
    maxValueHasFactor = WorkflowGraph()
    inputList = InputList()
    sortList = SortList()
    lastValueHasFactor = LastValueHasFactor()


    maxValueHasFactor.connect(inputList, 'output', sortList, 'input')
    maxValueHasFactor.connect(sortList, 'output', lastValueHasFactor, 'input')

    client.register_Workflow(maxValueHasFactor, 'Max_value_has_factor')


    #Word count workflow
    wordCount = WorkflowGraph()
    split = SplitLines()
    words = SplitWords()
    count = CountWords()



    wordCount.connect(split, 'output', words, 'input')
    wordCount.connect(words, 'output', count, 'input')

    client.register_Workflow(wordCount, 'Word_count')


# create workflows,
# retreive descriptions,
# put into table
def get_descriptions():

    client.get_Workflow("Astro_physics")
    client.get_Workflow("Clean_string")
    client.get_Workflow("Contains_B")
    client.get_Workflow("Is_prime")
    client.get_Workflow("Max_value_has_factor")
    client.get_Workflow("Word_count")

    return

def desc_search():
    print("Query: Workflow to calculate the star extinction")
    client.search_Registry("Workflow to calculate the star extinction", "workflow", "text")
    print("Query: find all factors")
    client.search_Registry("find all factors", "workflow", "text")
    print("Query: search for letter")
    client.search_Registry("search for letter", "workflow", "text")
    print("Query: list of primes")
    client.search_Registry("list of primes", "workflow", "text")

client = d4pClient()
print("\n Create User and Login \n")
client.register("testUser5","testUser5")
client.login("testUser5","testUser5")

# add_workflows()


# get_descriptions()


# desc_search()



def code_search():
    # ensure that workflows with more pes matching are ranked highest
    # ensure that workflows are then ranked by the pe similarity

    # generic search example to ensure functionality
    client.search_Registry('''def example():
                            
            response = requests.get(url)
            print('reading')
        
            return''', "workflow", "code")
    # code that appears once in one workflow and twice in another

    client.search_Registry('''
    return text.lower()''', "workflow", "code")


    # search that matches two, but one is a better match
    client.search_Registry('''                        
        for val in data:
            if maxVal % val == 0:
                print("Last value in list has factor in list")
                return
            elif all(val % i != 0 for i in range(2, num)):
                return val''', "workflow", "code")



code_search()