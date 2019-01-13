from traceutils.as2org.as2org cimport AS2Org
from traceutils.bgp.bgp cimport BGP

from bdrmapit_parser.algorithm.updates_dict cimport Updates, UpdateObj
from bdrmapit_parser.graph.construct cimport Graph
from bdrmapit_parser.graph.node cimport Router

cdef class Bdrmapit:
    cdef public Graph graph
    cdef public AS2Org as2org
    cdef public BGP bgp
    cdef public Updates lhupdates

    cpdef UpdateObj get(self, Router router, Updates updates);
    cpdef int get_asn(self, Router router, Updates updates) except *;
    cpdef str get_org(self, Router router, Updates updates);
    cpdef int get_utype(self, Router router, Updates updates) except *;
