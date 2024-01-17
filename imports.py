class _xml_to_dict(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, xmltree):
        '''
        Convert an XML tree into a dict
        '''
        if sys.version_info < (2, 7):
            children_len = len(xmltree.getchildren())
        else:
            children_len = len(xmltree)
    
        if children_len < 1:
            name = xmltree.tag
            if '}' in name:
                comps = name.split('}')
                name = comps[1]
            return {name: xmltree.text}
    
        xmldict = {}
        for item in xmltree:
            name = item.tag
            if '}' in name:
                comps = name.split('}')
                name = comps[1]
            if name not in xmldict:
                if sys.version_info < (2, 7):
                    children_len = len(item.getchildren())
                else:
                    children_len = len(item)
    
                if children_len > 0:
                    xmldict[name] = _xml_to_dict(item)
                else:
                    xmldict[name] = item.text
            else:
                if not isinstance(xmldict[name], list):
                    tempvar = xmldict[name]
                    xmldict[name] = []
                    xmldict[name].append(tempvar)
                xmldict[name].append(_xml_to_dict(item))
        return xmldict
