class _iptables_cmd(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, family='ipv4'):
        '''
        Return correct command based on the family, e.g. ipv4 or ipv6
        '''
        if family == 'ipv6':
            return salt.utils.path.which('ip6tables')
        else:
            return salt.utils.path.which('iptables')
