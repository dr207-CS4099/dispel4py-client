
from dispel4py.workflow_graph import WorkflowGraph 
from deep_learn_search import *
from typing import Union
from globals import *
import globals
import requests as req
import cloudpickle as pickle 
import codecs
import json 
import logging
import inspect 
import subprocess
from enum import Enum
import os 


import ConvertPy
from Aroma.similar import setup_features, compare_similar

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(message)s', level=logging.INFO) 

def verify_login():

    #check for client login session 
    if globals.CLIENT_AUTH_ID == "None":
        logger.info("You must be logged-in to perform this operation.")
        exit()

def create_import_string(pe_source_code: str):
     #write source code to file
    text_file = open("imports.py", "w")
    # TODO create reject warning from this, and allow program to keep running
    text_file.write(pe_source_code)
    text_file.close()

    #call find imports on file 
    output = subprocess.check_output("findimports -n imports.py",shell=True).decode()
    pe_imports = output.splitlines()
    del pe_imports[0]
    pe_imports = [s.strip().split('.', 1)[0] for s in pe_imports]

    #convert to string for ease 
    pe_imports = ','.join(pe_imports)

    return pe_imports

def serialize_directory(path):

    if path == None:
        return get_payload(None)

    data = {}

    for item in os.listdir(path):
        item_path = os.path.join(path,item)

        if os.path.isfile(item_path):

            with open(item_path, 'r') as f:
             file_contents = f.read()

            data[item] = {
                "type": "file",
                "size": os.path.getsize(item_path),
                "content": file_contents
            }

        elif os.path.isdir(item_path):

            data[item] = {
                "type":"directory",
                "contents": serialize_directory(item_path)
            }
    
    return get_payload(data)

def get_payload(code: any):

    #serialize code
    pickled = codecs.encode(pickle.dumps(code), "base64").decode()
    # print(len(pickled))
    return pickled

def get_objects(results):

    objectList = []

    print("\nREGISTRY\n")


    
    for index, result in enumerate(results,start=1):

        desc = result['description']

        if desc is None:
                desc = "-"

        if 'workflowName' in result.keys():
            workflow = "Result " + str(index) + ": " + "ID: " + str(result['workflowId']) + "\n" + "Workflow Name: " + result['entryPoint'] + "\n" + "Description: " + desc + "\n"
            obj = pickle.loads(codecs.decode(result['workflowCode'].encode(), "base64")) 
            print(workflow)
        else:
            pe_name = result['peName']
            pe = "Result " + str(index) + ": " + "ID: " + str(result['peId']) + "\n" + "PE Name: " +pe_name + "\n" + "Description: " + desc +"\n"
            obj = pickle.loads(codecs.decode(result['peCode'].encode(), "base64"))
            print(pe)

        objectList.append(obj)
    
    return objectList

class AuthenticationData:
    
    def __init__(
        self,
        *,
        user_name: str,
        user_password:str
    ):
    
        self.user_name = user_name
        self.user_password = user_password 

    def to_dict(self):
        return {
            "userName": self.user_name,
            "password": self.user_password
        }
    
    def __str__(self):
        return "AuthenticationData(" + json.dumps(self.to_dict(), indent=4) + ")"

class Process(Enum):
    SIMPLE = 1
    MULTI = 2
    DYNAMIC = 3

class PERegistrationData:
     
    def __init__(
        self,
        *,
        pe: type, 
        pe_name: str = None,
        pe_code: any = None,
        description: str = None
    ):

        if pe is not None: 
            pe_name = pe.__class__.__name__
        

       
        pe_source_code = inspect.getsource(pe.__class__)

        pe_process_source_code = inspect.getsource(pe._process)
        self.pe_name = pe_name 
        self.pe_code = get_payload(pe)

        if description:
            self.description = description
        else:
            self.description = generate_summary(pe_source_code).replace(" class ", " pe ")

        self.pe_source_code = pe_source_code
        self.pe_imports = create_import_string(pe_source_code)
        self.code_embedding = np.array_str(encode(pe_process_source_code,2).numpy())
        self.desc_embedding = np.array_str(encode(self.description,1).numpy())
        # self.desc_embedding = None

        # convert to json style file for AST similarity
        convertToAST = ConvertPy.ConvertPyToAST(pe_source_code, False)

        # featurisation allows for storing the relevant features for the similarity analysis
        featurisedAST = setup_features([convertToAST.result], "./Aroma")
        self.astEmbedding = str(json.dumps(featurisedAST))

    def to_dict(self):
        return {
            "peName": self.pe_name,
            "peCode": self.pe_code,
            "sourceCode": self.pe_source_code, 
            "description": self.description,
            "peImports": self.pe_imports,
            "codeEmbedding": self.code_embedding,
            "descEmbedding": self.desc_embedding,
            "astEmbedding" : self.astEmbedding
        }

    def __str__(self):
        return "PERegistrationData(" + json.dumps(self.to_dict(), indent=4) + ")"


    def __str__(self):
        return "PERegistrationData(" + json.dumps(self.to_dict(), indent=4) + ")"



class WorkflowRegistrationData:

    def __init__(
        self,
        *,
        workflow: any, 
        workflow_name: str = None,
        workflow_code: str = None,
        workflow_pes = None,  
        entry_point: str = None,
        description: str = None,
        desc_embedding: str = None,
    ):

        if workflow is not None: 
            workflow_name = workflow.__class__.__name__
            workflow_code = get_payload(workflow)
            


        workflow_pes = workflow.getContainedObjects() 
        workflow_source_code = "class " + entry_point + "():\n"
        for pe in workflow_pes:
            # print(inspect.getsource(pe.__class__))
            pe_code = inspect.getsource(pe.__class__)
            pe_code = pe_code.split("\n", 2)[2]
            workflow_source_code += pe_code
            workflow_source_code += "\n"
        # print(workflow_source_code)
        if description:
            self.description = description
        else:
            
            self.description = generate_summary(workflow_source_code).replace(" class ", " workflow ")

        
        self.workflow_name = workflow_name 
        self.workflow_code = workflow_code 
        self.entry_point = entry_point
        self.workflow_pes = workflow_pes
        self.desc_embedding = np.array_str(encode(self.description,1).numpy())

    def to_dict(self):
        
        return {
            "workflowName": self.workflow_name,
            "workflowCode": self.workflow_code,
            "entryPoint": self.entry_point,
            "description": self.description,
            "descEmbedding" : self.desc_embedding
            
        }
    
    def __str__(self):
        return "WorkflowRegistrationData(" + json.dumps(self.to_dict(), indent=4) + ")"

class ExecutionData:

    def __init__(
        self,
        *,
        workflow_id: int,
        workflow_name: str,
        workflow_code: WorkflowGraph, 
        input: any,
        process: Process,
        args: any,
        resources:str 
    ):  

        imports = ""

        if workflow_code is not None:
            #create import string    
            for pe in workflow_code.getContainedObjects():
                imports = imports + "," + create_import_string(inspect.getsource(pe.__class__))
        
        self.workflow_id = workflow_id 
        self.workflow_name = workflow_name 
        self.input = get_payload(input)
        self.workflow_code = get_payload(workflow_code)
        self.args = get_payload(args)
        self.process = process.value
        self.resources = serialize_directory(resources)
        self.imports = imports
     
    def to_dict(self):
        return {
            "workflowId": self.workflow_id,
            "workflowName": self.workflow_name,
            "workflowCode": self.workflow_code,
            "inputCode": self.input,
            "process": self.process,
            "args": self.args,
            "resources": self.resources,
            "imports": self.imports
        }

    def __str__(self):
        return "ExecutionData(" + json.dumps(self.to_dict(), indent=4) + ")"

class SearchData:

    def __init__(
        self,
        *,
        search: str, 
        search_type: bool
       
    ):
        self.search = search 
        self.search_type = search_type 
 
    def to_dict(self):
        return {
            "search": self.search,
            "searchType": self.search_type,
        }

    def __str__(self):
        return "SearchData(" + json.dumps(self.to_dict(), indent=4) + ")"

class WebClient:

    def __init__(): 
        None 
    
    def register_User(self,user_data: AuthenticationData):
        data = json.dumps(user_data.to_dict())
        response = req.post(URL_REGISTER_USER, data=data,headers=headers)
        response = json.loads(response.text)
        
        if 'ApiError' in response.keys():
            logger.error(response['ApiError']['message'])
            return None 
        else:
            logger.info("Sucessfully registered user: " + response["userName"] )
            return response["userName"]
    
    def login_User(self,user_data: AuthenticationData):
        data = json.dumps(user_data.to_dict())
        response = req.post(URL_LOGIN_USER, data=data,headers=headers)
        response = json.loads(response.text)
        
        if 'ApiError' in response.keys():
            logger.error(response['ApiError']['message'])
            return None 
        else:
            globals.CLIENT_AUTH_ID = response["userName"]
            logger.info("Sucessfully logged in: " + response["userName"])
            return response["userName"]

    def register_PE(self, pe_payload: PERegistrationData):

        verify_login()
        # TODO to deal with excessively large classes, it may become worthwhile to send
        # each function indivually
        data = json.dumps(pe_payload.to_dict())
        response = req.post(URL_REGISTER_PE.format(globals.CLIENT_AUTH_ID), data=data,headers=headers)
        # print(response)
        response = json.loads(response.text)

        if 'ApiError' in response.keys():
            logger.error(response['ApiError']['debugMessage'])
            return None 
        else: 
            pe_id = response["peId"]
            logger.info("Successfully registered PE " + response["peName"] + " with ID " + str(pe_id))
            return int(pe_id)
       
    def register_Workflow(self, workflow_payload: WorkflowRegistrationData):

        verify_login()

        workflow_dict = workflow_payload.to_dict()
        # print(workflow_dict['descEmbedding'])
        data = json.dumps(workflow_dict)

        response = req.post(URL_REGISTER_WORKFLOW.format(globals.CLIENT_AUTH_ID), data=data,headers=headers) #add workflow resources 
        response = json.loads(response.text)

        if 'ApiError' in response.keys():
            logger.error(response['ApiError']['message'])
            return None 
        else: 

            workflow_id = response['workflowId']

            #Link PEs to Workflow 
            for pe_obj in workflow_payload.workflow_pes:

                get_pe_url = URL_GET_PE_NAME.format(globals.CLIENT_AUTH_ID) + pe_obj.name 
                pe_res = req.get(url=get_pe_url)
                pe_res = json.loads(pe_res.text)

                if 'ApiError' in pe_res.keys():
                    #register PE
                    data = PERegistrationData(pe=pe_obj)
                    pe_id = WebClient.register_PE(self,data)
                    #Link PE
                    req.put(url=URL_LINK_PE_TO_WORKFLOW.format(globals.CLIENT_AUTH_ID,workflow_id,pe_id))
                else:
                    req.put(url=URL_LINK_PE_TO_WORKFLOW.format(globals.CLIENT_AUTH_ID,workflow_id,pe_res["peId"]))
                    #Link PE to Workflow 
                    
            logger.info("Successfully registered Workflow: " + response["entryPoint"] + " ID:" + str(response["workflowId"]))
            return response["workflowId"]

    def run(self, execution_payload: ExecutionData):

        verify_login()

        data = json.dumps(execution_payload.to_dict())

        # print(data)

        response = req.post(url=URL_EXECUTE.format(globals.CLIENT_AUTH_ID),data=data,headers=headers)

        response = json.loads(response.text)

        if 'ApiError' in response.keys():
            logger.error(response['ApiError']['message'])
            return None 
        else:   
            # print(response)
            result = response["result"]
            logger.info("Successfully executed workflow: ")
            logger.info(result)
            return result

    def get_PE(self, pe: Union[int,str]):

        verify_login()

        if isinstance(pe, str):
            
            url = URL_GET_PE_NAME.format(globals.CLIENT_AUTH_ID) + pe
            
        elif isinstance(pe, int):

            url = URL_GET_PE_ID.format(globals.CLIENT_AUTH_ID) + str(pe)
        else:
            assert 'invalid type'

        response = req.get(url=url)
        response = json.loads(response.text)

        if 'ApiError' in response.keys():
            logger.error(response['ApiError']['message'])
            return None 

        else: 
            logger.info("Successfully retrieved PE " + response["peName"])
            peCode = response["peCode"]
            unpickled_result = pickle.loads(codecs.decode(peCode.encode(), "base64"))
            return unpickled_result

    def get_Workflow(self, workflow: Union[int,str]):

        verify_login()

        if isinstance(workflow, str): 
            url = URL_GET_WORKFLOW_NAME.format(globals.CLIENT_AUTH_ID) + workflow

        elif isinstance(workflow, int):

            url = URL_GET_WORKFLOW_ID.format(globals.CLIENT_AUTH_ID) + str(workflow)

        response = req.get(url=url)
        response = json.loads(response.text)

        if 'ApiError' in response.keys():
            logger.error(response['ApiError']['message'])
            return None 

        else: 
            logger.info("Successfully retrieved Workflow " + response["entryPoint"])
            logger.info("Workflow Description: " + str(response["description"]))
            workflowCode = response["workflowCode"]
            unpickled_result: WorkflowGraph = pickle.loads(codecs.decode(workflowCode.encode(), "base64"))
            return unpickled_result

    def get_PEs_By_Workflow(self, workflow: Union[int,str]):

        verify_login()

        if isinstance(workflow, str):
            
            url = URL_GET_PE_BY_WORKFLOW_NAME.format(globals.CLIENT_AUTH_ID) + workflow
            
        if isinstance(workflow, int):

            url = URL_GET_PE_BY_WORKFLOW_ID.format(globals.CLIENT_AUTH_ID) + str(workflow)

        response = req.get(url=url)
        response = json.loads(response.text)

        objectList = []


        for index, response in enumerate(response,start=1):
            pe_name = response['peName']
            pe_desc = response['description']

            if pe_desc is None:
                pe_desc = "-"

            pe = "Result " + str(index) + ": \n" + "ID: " + str(response['peId']) + "\n" + "PE Name: " + pe_name + "\n" + "Description: " + pe_desc +"\n"
            obj = pickle.loads(codecs.decode(response['peCode'].encode(), "base64"))
            # print(pe)

            objectList.append(obj)
        
        return objectList

    def remove_PE(self,pe: Union[int,str]):

        verify_login()

        if isinstance(pe, str):
            
            url = URL_REMOVE_PE_NAME.format(globals.CLIENT_AUTH_ID) + pe
            
        if isinstance(pe, int):

            url = URL_REMOVE_PE_ID.format(globals.CLIENT_AUTH_ID) + str(pe)
        
        response = req.delete(url=url)
        response = json.loads(response.text)

        if response == 1:
            logger.info("Sucessfully removed PE: " + str(pe))
        else:
            logger.error(response['ApiError']['message'])

    def remove_Workflow(self,workflow:Union[int,str]):

        verify_login()

        if isinstance(workflow, str):
            
            url = URL_REMOVE_WORKFLOW_NAME.format(globals.CLIENT_AUTH_ID) + workflow
            
        if isinstance(workflow, int):

            url = URL_REMOVE_WORKFLOW_ID.format(globals.CLIENT_AUTH_ID) + str(workflow)
        
        response = req.delete(url=url)
        response = json.loads(response.text)

        if response == 1:
            logger.info("Sucessfully removed Workflow: " + str(workflow))
        else:
            logger.error(response['ApiError']['message'])



            
    def desc_similarity(self, search_payload: SearchData, search_type):
        verify_login()
        search_dict = search_payload.to_dict()

        if(search_type == "workflow"):
            url = URL_WORKFLOW_ALL.format(globals.CLIENT_AUTH_ID)
        else:
            url = URL_PE_ALL.format(globals.CLIENT_AUTH_ID)

        
        response = req.get(url=url)
        response = json.loads(response.text)
        
        return similarity_search(search_dict['search'], response, "text", search_type)

    def search(self,search_payload: SearchData):

        verify_login()

        search_dict = search_payload.to_dict()

        
        url = URL_SEARCH.format(globals.CLIENT_AUTH_ID,search_dict['search'], search_dict['searchType'])
        print(url)
        response = req.get(url=url)
        response = json.loads(response.text)

        # If this fails, then do lookup on the description
        # print(response)
        return get_objects(response)
    

    # workflow similarity based on code - code search
    def workflow_search_similarity(self, search_payload: SearchData):
        # find pes similar to the code provided
        _ , similarPEs = WebClient.search_similarity(self, search_payload)

        
        # find workflows that contain these pes
        url = URL_GET_WORKFLOW_BY_PE.format(globals.CLIENT_AUTH_ID)
        
        objectList = []
        index = 0
        # recall that dictionaries are order post python 3.7
        discoveredWorkflows = []
        workflowPositions = {} # used to find the index by workflow
        for pe in similarPEs:
            
            response = req.get(url=url + str(pe[0]))
            response = json.loads(response.text)
            
            # add response to list of discovered
            # remove any duplicates
            for result in response:
                if not result[0] in workflowPositions:
                    workflowPositions[result[0]] = index
                    discoveredWorkflows.append([result[0], result[1], result[2], result[3], index, 1])
                    index += 1
                else:
                    discoveredWorkflows[workflowPositions[result[0]]][5] += 1


        # sort by number of occurences, break ties by position
        # 
        discoveredWorkflows = sorted(discoveredWorkflows, key=lambda x: (-x[5], x[4]))
        resultPos = 0
        for workflow in discoveredWorkflows:

            print("Result " + str(resultPos) + ": " + "ID: " + str(workflow[0]) + "\n" + "Workflow Name: " + workflow[1] + "\n" + "Description: " + workflow[2] + "\n")

            objectList.append(pickle.loads(codecs.decode(workflow[3].encode(), "base64")))
               

            resultPos += 1
        return objectList
    
    def search_similarity(self, search_payload: SearchData):
        verify_login()
        search_dict = search_payload.to_dict()

        url = URL_PE_ALL.format(globals.CLIENT_AUTH_ID)

        response = req.get(url=url)
        response = json.loads(response.text)
        
        # print(response[0]['astEmbedding'])
        astEmbeddings = []

        # puts all of the pe embeddings into a list
        # TODO handle bad responses
        for pe in response:
            # print(pe['astEmbedding'][1])
            # concat instead of appending
            jsonData = None
            jsonData = json.loads(pe['astEmbedding'])
            
            # adds the pe name and id to each function
            for func in jsonData:

                func['peId'] = pe['peId']
                func['peName'] = pe['peName']
            

            astEmbeddings += jsonData

        # convert to json style file for AST similarity


        

        convertToAST = ConvertPy.ConvertPyToAST(search_payload.search, False)
        setup_features([astEmbeddings], "./Aroma")
          
        result = []
        for converted in convertToAST.result:
            result += compare_similar(astEmbeddings, [converted], "./Aroma")


        return similarity_search(search_dict['search'], response, "code", "pe"), result

    def get_Registry(self):

        verify_login()
        
        url = URL_REGISTRY_ALL.format(globals.CLIENT_AUTH_ID)

        response = req.get(url=url)
        response = json.loads(response.text)

        return get_objects(response)
