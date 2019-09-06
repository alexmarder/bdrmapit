from traceutils.radix.ip2as cimport IP2AS

cpdef enum OutputType:
    WARTS = 1
    ATLAS = 2
    ATLAS_ODD = 3


cdef class TraceFile:
    cdef public str filename
    cdef public OutputType type


cdef class ParseResults:
    cdef readonly set addrs, adjs, dps, mpls, spoofing, echos, cycles

    cpdef void update(self, ParseResults results) except *;


cpdef ParseResults parse(TraceFile tfile);
cdef dict listify(d);
cpdef dict build_graph_json(ParseResults parseres, IP2AS ip2as);