class ProvenanceLogger(GenericPE):
    def __init__(self):
        GenericPE.__init__(self)
        self.inputconnections = {"metadata": {NAME: "metadata"}}

    def process(self, inputs):
        try:
            metadata = inputs["metadata"]
            self.log(f"Logging metadata: {str(metadata)[:300]}")
        except:
            self.log(traceback.format_exc())
