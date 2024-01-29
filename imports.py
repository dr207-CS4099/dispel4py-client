class Getoutput_20050(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, cmd):
        """Return standard output of executing cmd in a shell.
    
        Accepts the same arguments as os.system().
    
        Parameters
        ----------
        cmd : str
          A command to be executed in the system shell.
    
        Returns
        -------
        stdout : str
        """
    
        out = process_handler(cmd, lambda p: p.communicate()[0], subprocess.STDOUT)
        if out is None:
            return ''
        return py3compat.bytes_to_str(out)
