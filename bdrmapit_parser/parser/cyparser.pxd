from traceutils.radix.ip2as cimport IP2AS

cpdef enum OutputType:
    WARTS = 1
    ATLAS = 2


cdef class TraceFile:
    cdef public str filename
    cdef public OutputType type


cpdef tuple parse(TraceFile tfile);
cdef dict listify(d);
cpdef dict build_graph_json(set addrs, set adjs, set dps, IP2AS ip2as);