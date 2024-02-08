class Dict_repr_html_25(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, dictionary):
        """
        Jupyter Notebook magic repr function.
        """
        rows = ''
        s = '<tr><td><strong>{k}</strong></td><td>{v}</td></tr>'
        for k, v in dictionary.items():
            rows += s.format(k=k, v=v)
        html = '<table>{}</table>'.format(rows)
        return html
