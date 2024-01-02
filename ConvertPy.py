import sys
# antlr4 -v 4.13.0 -Dlanguage=Python3 PythonParser.g4
from antlr4 import * #antlr4-python3-runtime==4.13.1
from antlr4.tree.Trees import Trees
from PythonLexer import PythonLexer
from PythonParser import PythonParser
from antlr4.tree.Tree import TerminalNode, TerminalNodeImpl, Tree, ParseTree
import json

# for reading in as string
from io import StringIO # Python 3 import



# from VisitorInterp import VisitorInterp

# translated from facebook aroma ConvertJava.java

# TODO change these to being passed through?

# this might actually be more efficient as we are not building a stack
# and we theoretically are not multi threading so no need to be thread safe

# suspected bug with pythonLexer.py produced by antlr,
# in other language (ie Java) it is interpreted to include null for names that do not have a literal conversion
# pythonLexer.py does not, and without them, the names do not match the appropriate token values
expectedLiteralNames = [None, None, None, None, None, None, "'False'", "'await'", "'else'", "'import'", 
		"'pass'", "'None'", "'break'", "'except'", "'in'", "'raise'", "'True'", 
		"'class'", "'finally'", "'is'", "'return'", "'and'", "'continue'", "'for'", 
		"'lambda'", "'try'", "'as'", "'def'", "'from'", "'nonlocal'", "'while'", 
		"'assert'", "'del'", "'global'", "'not'", "'with'", "'async'", "'elif'", 
		"'if'", "'or'", "'yield'", "'('", "'['", None, "')'", "']'", None, "'.'", 
		"':'", "','", "';'", "'+'", "'-'", "'*'", "'/'", "'|'", "'&'", "'<'", 
		"'>'", "'='", "'%'", "'=='", "'!='", "'<='", "'>='", "'~'", "'^'", "'<<'", 
		"'>>'", "'**'", "'+='", "'-='", "'*='", "'/='", "'%='", "'&='", "'|='", 
		"'^='", "'<<='", "'>>='", "'**='", "'//'", "'//='", "'@'", "'@='", "'->'", 
		"'...'", "':='", "'!'"]
#retrieved from lexer
symbolicNames = []
identifiersRuleNames = [
            "IDENTIFIER",
            "localVar",
            "CHAR_LITERAL",
            "STRING_LITERAL",
            "BOOL_LITERAL",
            "NULL_LITERAL",
            "DECIMAL_INTEGER",
            "HEX_INTEGER",
            "OCT_INTEGER",
            "BINARY_INTEGER",
            "FLOAT_NUMBER",
            "NAME"]
localVarContexts = ["atom"]

# TODO use a class for these probably
stackDepth = 0
MAX_DEPTH = 1000
childHasLeaf = False # TODO?
ruleNames = []
beginLine = 0
endLine = 0
totalMethods = 0
thisFileName = ""
thisClassName = ""
thisMethodName = ""
outputFile = ""
# Python Lexer does not provide the appropriate Vocabulary class
# this provides the functionality of the java python lexer of
# taking either the literal name or symbolic name
def getDisplayName(tokenType):
    global expectedLiteralNames, symbolicNames
    if(tokenType < len(expectedLiteralNames) and expectedLiteralNames[tokenType] != None):
        return expectedLiteralNames[tokenType]
    return symbolicNames[tokenType]

def setSymbolicNames(lexer):
    global symbolicNames
    symbolicNames = lexer.symbolicNames

def setRuleNames(parser):
    global ruleNames
    ruleNames = parser.ruleNames
def getRuleName(tree):
    global ruleNames

    # print(ruleNames)
    # print(tree.getRuleIndex())
    return ruleNames[tree.getRuleIndex()]

# gets the text leading / trailing the token
# (ie the indentation and line breaks etc)
def getLeadingOrTrailing(tree, tokens, isBefore):
    lastIndexOfToken = tree.getSymbol().tokenIndex
    ws = None
    text = ""
    HIDDEN = 1
    if(lastIndexOfToken < 0):
        # print("hello world")
        return ""
    if(isBefore):
        ws = tokens.getHiddenTokensToLeft(lastIndexOfToken, HIDDEN)
    elif(lastIndexOfToken >= 0 or lastIndexOfToken == -2):
        ws = tokens.getHiddenTokensToRight(lastIndexOfToken, HIDDEN)
    if(ws != None):
        for wst in ws:
            # TODO consider optimisation
            text += wst.text
    return text
def dumpMethodAST(thisRuleName, simpleTree):
    global thisFileName, thisClassName, thisMethodName, beginLine, endLine, totalMethods, outputFile
    # TODO do we actually care about there being a class?
    # only write the functions to the JSON file, to avoid duplication
    if (thisClassName != None and thisRuleName == "function_def_raw"):
        # print(simpleTree)
        # TODO what is this doing?
        if(len(simpleTree) == 2):
            try:
                simpleTree = json.dumps(simpleTree[1])
            except:
                return 
        tmp = {}
        tmp["path"] = thisFileName
        tmp["class"] = thisClassName
        tmp["method"] = thisMethodName
        tmp["beginline"] = beginLine
        tmp["endline"] = endLine
        tmp["ast"] = simpleTree

        # write to file
        print("writing to file")
        f = open(outputFile, "a")
        json.dump(tmp, f)
        # f.write(str(tmp))
        f.close()


        totalMethods += 1

def setClassName(thisRuleName, tree, i):
    if(thisRuleName == "class_def_raw" and i > 0):
        prev = tree.getChild(i - 1)
        curr = tree.getChild(i)

        # (class and name should be leaf nodes)
        if(prev is TerminalNodeImpl and curr is TerminalNodeImpl
            and prev.getText() == "class"):
            thisToken = curr.getSymbol()
            ruleName = getDisplayName(thisToken.type)

            # set the class name
            if(ruleName == "NAME"):
                thisClassName = thisToken.getText()

# convert the AST into a json AST for the similarity comparision
def getSerializedTree(tree, tokens: CommonTokenStream):
    global stackDepth, childHasLeaf, thisClassName, thisMethodName, beginLine
    stackDepth += 1
    numChildren = tree.getChildCount()
    hasLeaf = False
    # if we are at the end of a leaf, we go no further
    if(numChildren == 0 or stackDepth > MAX_DEPTH):
        childHasLeaf = False
        stackDepth -= 1
        return None

    thisRuleName = getRuleName(tree)
    oldClassName = None
    oldMethodName = None
    oldBeginLine = 0


    # set the class name
    if(thisRuleName == "class_def_raw"):
        oldClassName = thisClassName

    # set the function name
    if (thisRuleName == "func_def_raw"):
        oldMethodName = thisMethodName
        thisMethodName = tree.getChild(1).getText()

    simpleTree = []
    simpleTree.append("")

    # TODO consider using as string builder etc
    text = ""
    # TODO consider optimisation
    # https://stackoverflow.com/questions/2414667/python-string-class-like-stringbuilder-in-c

    for i in range(numChildren):
        childTree = tree.getChild(i)
        # is a leaf
        if(isinstance(childTree, TerminalNodeImpl)):
            s = childTree.getText()
            if(not s == "<EOF>"):

                thisToken = childTree.getSymbol()
                ruleName = getDisplayName(thisToken.type)
                # print(ruleName)

                # get leading and trailing chars (ie indentation / line breaks etc)
                ws1 = getLeadingOrTrailing(childTree, tokens, True)
                ws2 = getLeadingOrTrailing(childTree, tokens, False)
                tok = {}
                # print(s)
                tok["token"] = s
                tok["leading"] = ws1
                tok["trailing"] = ws2
                
                isLeaf = False

                if(ruleName in identifiersRuleNames):
                    if(thisRuleName in localVarContexts):
                        tok["var"] = True
                        
                    isLeaf = True
                    text += "#"
                    hasLeaf = True
                    setClassName(thisRuleName, tree, i)
                else:
                    isLeaf = False
                    text += s
                
                # TODO can this be put in the if above?
                if isLeaf: tok["leaf"] = isLeaf
                tok["line"] = thisToken.line
                simpleTree.append(tok)
            
        # not a leaf
        else:
            child = getSerializedTree(childTree, tokens)
            if(child != None and len(child) > 0):
                if(len(child) == 2):
                    simpleTree.append(child[1])
                    text += child[0]
                    hasLeaf = hasLeaf or childHasLeaf
                    
                elif(not childHasLeaf):
                    text += child[0]
                    for j in range(1, len(child)):
                        simpleTree.append(child[j])
                
                else:
                    text += "#"
                    hasLeaf = True
                    simpleTree.append(child)

    simpleTree.insert(0, text)
    childHasLeaf = hasLeaf

    dumpMethodAST(thisRuleName, simpleTree)

    # revert the class name
    if(thisRuleName == "class_def_raw"):
        thisClassName = oldClassName

    # revert the function name
    if (thisRuleName == "func_def_raw"):
        thisMethodName = oldMethodName
        beginLine = oldBeginLine

    stackDepth -= 1
    return simpleTree


# call from client
def convertPy(code_str):
    global vocab



# run from command line
def main(argv):
    global vocab, outputFile

    input_stream = FileStream(argv[1])
    outputFile = argv[2]
    lexer = PythonLexer(input_stream)
    vocab = lexer.symbolicNames

    stream = CommonTokenStream(lexer)
    parser = PythonParser(stream)
    # print(parser)
    tree = parser.file_input()
    # print()
    # print(Trees.toStringTree(tree, None, parser))
    # print(tree.toStringTree(parser))
    # print(parser.ruleNames)

    setRuleNames(parser)
    setSymbolicNames(lexer)
    getSerializedTree(tree, stream)
    

if __name__ == '__main__':
    # print("hello world")
    main(sys.argv)