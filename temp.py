from ConvertToPE import *



testStr = \
'''def testFunc():
        if(True and 2==2):
            print("example")
            print("test")'''  

ConvertToPE(testStr, True)