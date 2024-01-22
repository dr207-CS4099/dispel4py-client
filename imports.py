class Deploy(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Deploy salt-thin
            '''
            self.shell.send(
                self.thin,
                os.path.join(self.thin_dir, 'salt-thin.tgz'),
            )
            self.deploy_ext()
            return True
