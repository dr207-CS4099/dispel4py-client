from dispel4py.base import ConsumerPE
from dispel4py.base import IterativePE
from dispel4py.base import ProducerPE


# workflow to check process file
class InitialString(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)

    def _process(self):
        # produces initial string
        return "The quick brown fox jumped over the lazy dog"

class ToLower(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)

    def _process(self, text):
        return text.lower() 

class ContainsB(ConsumerPE):
    # checks if a string contains B

    def __init__(self):
        ConsumerPE.__init__(self)

    def _process(self, text):
        if 'b' in text.lower():
            print("Contains B")
        else:
            print("Does not contain B")

