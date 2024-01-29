# Client Instructions 

The following instructions will allow you to run the client application to run dispel4py workflows 

Clone repository 
```
git clone https://github.com/dr207-CS4099/dispel4py-client.git
```
Then enter directory by 
```
cd dispel4py-client
```
In order to run the application you need to create a new Python 3.10 enviroment 
```
--note conda must be installed beforehand, go to https://conda.io/projects/conda/en/stable/user-guide/install/linux.html
conda create --name py10 python=3.10
conda activate py10
--or venv (recommended for lab machines)
python -m venv .
```
(for lab machines upgrade pip)
```
pip install --upgrade pip
```

Install dispel4py 
```
git clone https://github.com/dispel4py2-0/dispel4py.git
cd dispel4py
pip install -r requirements.txt
python setup.py install
cd ..
```
Test dispel4py 
```
dispel4py simple dispel4py.examples.graph_testing.word_count -i 10
```
Install client modules
```
pip install -r requirements_client.txt
```

# Evaluation
To replicate the evaluation data
```
python evaluation.py
```
This uses the "code_search_net" python corpus, downloaded from hugging_face, and pairs functions together that have idential documentation strings, this is done by iterating through the dataset and storing each unique documentation string, along with the relevant code, and when we find a duplicate documentation string, we create a pairing. This pairing contains the pe1, that is func1 converted to a PE to be uploaded to the database, and the func2 code that is semantically similar. This func2 code is later used to attempt to retrieve pe1, from the database.

Once we have iterated through the dataset, the pes are dumped to data.py so that they can be easily uploaded using client.register_PE(). The pairings are stored in data.json, so that we can use these to search the database using client.search_Registry().

In future this will include how this data can be emperically analysed.


# Converting from function to PE
The file ConvertToPE.py takes a function and attempts to convert it to a PE. Currently the valid types of PE are: 

ProducerPE (takes no input, returns an output)
IterativePE (takes an input, returns an output)
ConsumerPE (takes an input, returns no output)

Functions that take more than one input, or return more than one output are rejected.

If the function is of an appropriate form, thne it creates a class with the name taken from the name of the received function, an appropriate __init__() for the type of PE and the function code is converted into a _process() with self and then the input parameter if one is expected.

This allows generic functions to be stored within the database and used within dispel4py seamlessly.


# Getting started with code-to-code search in Laminar
Running uploadExamples.py will upload a small sample of PEs to the database, an example of expected search inputs can be seen in sentiPEs.py. This will provide the user with a feel for the functionality of this program.


```
python uploadEamples.py
python sentiPEs.py
```
