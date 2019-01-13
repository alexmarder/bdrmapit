from traceutils.radix.ip2as cimport IP2AS

cpdef enum OutputType:
    WARTS = 1
    ATLAS = 2


cdef class TraceFile:
    cdef public str filename
    cdef public OutputType type


cpdef tuple parse(str filename, OutputType output_type, IP2AS ip2as, set addrs=*, set adjs=*, set dps=*);
