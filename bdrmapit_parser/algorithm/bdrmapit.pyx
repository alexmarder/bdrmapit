from traceutils.as2org.as2org cimport AS2Org
from traceutils.bgp.bgp cimport BGP

from bdrmapit_parser.algorithm.updates_dict cimport Updates, UpdatesView, UpdateObj
from bdrmapit_parser.graph.construct cimport Graph
from bdrmapit_parser.graph.node cimport Router


cdef class Bdrmapit:

    def __init__(self, Graph graph, AS2Org as2org, BGP bgp, Updates lhupdates=None):
        self.graph = graph
        self.as2org = as2org
        self.bgp = bgp
        if lhupdates is None:
            self.lhupdates = Updates()
        else:
            self.lhupdates = UpdatesView(lhupdates)

    cpdef UpdateObj get(self, Router router, Updates updates):
        result = self.lhupdates[router]
        if result:
            return result
        return updates[router]

    cpdef int get_asn(self, Router router, Updates updates) except *:
        result = self.get(router, updates)
        if result:
            return result.asn
        return -1

    cpdef str get_org(self, Router router, Updates updates):
        return self.get(router, updates).org

    cpdef int get_utype(self, Router router, Updates updates) except *:
        return self.get(router, updates).utype
