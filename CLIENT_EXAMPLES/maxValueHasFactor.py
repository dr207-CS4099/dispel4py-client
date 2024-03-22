from dispel4py.base import ConsumerPE
from dispel4py.base import IterativePE
from dispel4py.base import ProducerPE

class InputList(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)

    def _process(self):
        inputList = [4,8,7,3,2,9]

        return inputList
    

class SortList(IterativePE):

    def __init__(self):
        IterativePE.__init__(self)

    def _process(self, data):

        return data.sort()

class LastValueHasFactor(ProducerPE):
    def __init__(self):
        IterativePE.__init__(self)

    def _process(self, data):
        
        maxVal = data[len(data)-1]

        for val in data:
            if maxVal % val == 0:
                print("Last value in list has factor in list")
                return
            print("Last value does not have factor in list")