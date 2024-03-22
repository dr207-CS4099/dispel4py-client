from dispel4py.base import ConsumerPE
from dispel4py.base import IterativePE
from dispel4py.base import ProducerPE
import string

class InputString(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)

    def _process(self):
        inputString = "This is an input; we wAnt to NORmalise the input!"
        return inputString

# remove punction
class RemovePunctuation(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)

    def _process(self, text):
        text.translate(str.maketrans('', '', string.punctuation))

        return text
# convert to lower case
class WordsToLower(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)

    def _process(self, text):

        return text.lower()
    
# split on spaces
class SplitOnSpaces(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)

    def _process(self, text):
        return text.split()

# print string
    

class PrintString(ConsumerPE):

    def __init__(self):
        ConsumerPE.__init__(self)

    def _process(self, text):
        print("The output string is " + str(text))