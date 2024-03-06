from web_client import *
from globals import *
from dispel4py.base import *
from dispel4py.workflow_graph import WorkflowGraph
from dispel4py.visualisation import display
from typing_extensions import Literal, get_args
from web_client import WebClient
from typing import Union
_TYPES = Literal["pe", "workflow", "both"]

_QUERY_TYPES = Literal["text","code"]
 
class d4pClient:

    """Class to interact with registry
    and server services"""

    def __init__(self):
        None
    
    def register(self, user_name:str, user_password:str):
        """ Register a user with the Registry service 

        Parameters
        ----------
        user_name:str
            Username
        user_password: str
            User password

        Return 
        ------
        user_name: str
            Username
        """

        data = AuthenticationData(
            user_name=user_name,
            user_password=user_password
        )

        return WebClient.register_User(self,data)

    def login(self,user_name:str,user_password:str):
        """Login user to use Register service 

        Parameters
        ----------
        user_name:str
            Username
        user_password: str
            User password

        Return 
        ------
        user_name: str
            Username
        """
        
        data = AuthenticationData(
            user_name=user_name,
            user_password=user_password
        )

        return WebClient.login_User(self,data)
     
    def register_PE(self,pe: PE_TYPES,description:str=None):

        """Register a PE with the client service
        
        Parameters
        ----------
        pe: dispel4py Processing Element
           PE object 
        description: str
            Description of PE

        Return 
        -------
        id: int
            ID for registered PE
        """

        data = PERegistrationData(
            pe=pe,
            description=description
        )
    
        return WebClient.register_PE(self,data)
    
    def register_Workflow(self,workflow: WorkflowGraph,workflow_name:str,description:str=None):
        
        """Register a Workflow with the client service 

        Parameters 
        ----------
        workflow: dispel4py WorkflowGraph
                Workflow object
        workflow_name: str 
                Entrypoint of workflow 
        description: str 
                Description of workflow 
        Return 
        -------
        id: int
                ID for registered workflow 
        """

        data = WorkflowRegistrationData(
                workflow = workflow,
                entry_point = workflow_name,
                description = description
            )   

        return WebClient.register_Workflow(self,data)

    def run(self,workflow:Union[str,int,WorkflowGraph],input=None,process=Process.SIMPLE,args=None,resources:bool=False):

        """Execute a Workflow with the client service 

        Parameters 
        ----------
        workflow: int/str/WorkflowGraph
                Workflow to execute 
        input: any 
                Input to execute 
        process: Process (Simple/Multi/Dynamic) 
                Execution method
        resources: bool 
                If require resources for workflow execution 
        Return 
        -------
        result: str
                Output from executing workflow 

        """

        workflow_id = None
        workflow_name = None
        workflow_code = None 

        if isinstance(workflow, str): #Name
           workflow_name = workflow 
        elif isinstance(workflow, int): #ID
           workflow_id = workflow
        elif isinstance(workflow, WorkflowGraph): # Graph 
           workflow_code = workflow 
          
        if input is None:
            #todo do something
            None

        if args is None and (process == 2 or process == 3):
            assert 'Must provide ''args'' for Multi\Dynamic process'

        if resources is True: 
            resources_path = "resources/"
        else: 
            resources_path = None
        
        data = ExecutionData(
            workflow_id = workflow_id,
            workflow_name = workflow_name,
            workflow_code = workflow_code,
            input = input,
            process = process,
            args = args,
            resources = resources_path
        )
        
        return WebClient.run(self,data)

    def get_PE(self,pe:Union[str,int],describe:bool=False):

        """Retrieve PE from resgistry 

        Parameters 
        ----------
        pe: str/int
            Name or ID of PE to retrieve
        describe: bool 
            True - provides description of PE   
        Return 
        -------
        PE: Class 
            PE Class
        """

        pe_obj = WebClient.get_PE(self,pe)
        
        if describe and pe_obj:
            WebClient.describe(pe_obj)

        return pe_obj

    def get_Workflow(self,workflow:Union[str,int],describe:bool = False):

        """Retrieve Workflow from resgistry 

        Parameters 
        ----------
        workflow: str/int
            Name or ID of Workflow to retrieve
        describe: bool 
            True - provides description of Workflow  

        Return 
        -------
        Workflow: WorkflowGraph 
            Workflow Class
        """
        workflow_obj = WebClient.get_Workflow(self,workflow)
        
        if describe and workflow_obj:
            WebClient.describe(self,workflow)

        return workflow_obj
    
    def search_Registry(self, search:str, search_type:_TYPES = "both", query_type:_QUERY_TYPES = "text"):
        """Search registry for workflow 
        
        Parameters
        ----------
        search: str
           Search string 
        includePE: "both"/"pe"/"workflow" 
            "both" - Searches registry for both workflow or PE 
            "pe" - Only searches for PE 
            "workflow" - Only searches for workflow
        Return 
        -------
        results: list 
            List of Workflow and/or PE objects  
        """

        options = get_args(_TYPES)
        assert search_type in options, f"'{search_type}' is not in {options}"

        data = SearchData(
            search= search,
            search_type = search_type,
        )

        # logger.info("Searched for \"" + search + "\"")
        # TODO seperate text from code search here
        #Performing search similarity for PEs
        if query_type == "code":
            if search_type == "pe": 
            
                return WebClient.search_similarity(self,data)
            elif search_type == "workflow": # TODO handle both

                return WebClient.workflow_search_similarity(self, data)
        
        else:
            return WebClient.desc_similarity(self,data, search_type)
    
    def describe(self, obj:any):
        """Describe PE or Workflow object 
        
            Parameters
            ----------
            obj: WorkflowGraph or PE
                Object to describe 
        """

        if isinstance(obj,WorkflowGraph):
            
            workflow_pes = [o.name for o in obj.getContainedObjects()] 

            print("PEs in Workflow: ", workflow_pes)
            #display(obj)
           
        elif isinstance(obj,PE_TYPES):
            
            print("PE name:", getattr(obj,"name"))

            for item, amount in obj.__dict__.items(): 
                if item in ["wrapper","pickleIgnore","id","name"]:
                    continue

                print("{}: {} ".format(item, amount))
 
        else:    
            assert isinstance(obj, type), "Requires an object of type WorkflowGraph or PE" 
    
    def remove_PE(self,pe:Union[str,int]):
        """Remove PE from Registry
        
            Parameters
            ----------
            pe: str/int
                PE Name or ID to remove 
        """
        WebClient.remove_PE(self,pe)

    def remove_Workflow(self,workflow:Union[str,int]):
        """Remove Workflow from Registry  
        
            Parameters
            ----------
            workflow: str/int
                Workflow Name or ID to remove 
        """
        WebClient.remove_Workflow(self,workflow)

    def get_PEs_By_Workflow(self,workflow:Union[str,int]):

        """Retrieve PEs in Workflow 

        Parameters 
        ----------
        workflow: str/int
            Name or ID of Workflow to retrieve
         
        Return 
        -------
        pes: list 
            List of PEs
        """
        
        return WebClient.get_PEs_By_Workflow(self,workflow)

    def get_Registry(self):

        """Retrieve Registry 

        Return 
        -------
        registry: list 
            List of PEs/Workflows
        """

        return WebClient.get_Registry(self)
    
    