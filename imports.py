class InternalExtinction(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, data):
        count, ra, dec = data[0:3]
        mtype = data[3]
        logr25 = data[4]
        print("!! DATA mytype:%s, logr25:%s" %(mtype,logr25))
        try:
            t, ai = internal_extinction(mtype, logr25)
            result = [count, ra, dec, mtype, logr25, t, ai]
            print('internal extinction: %s' % result)
            return result
        except:
            print('KIG%s: failed to calculate internal extinction' % count)
