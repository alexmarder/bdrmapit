from traceutils.as2org.as2org cimport AS2Org
from traceutils.radix.ip2as cimport IP2AS

cdef class Graph:
    cdef readonly dict interfaces, routers

cpdef Graph construct_graph(list addrs, dict nexthop, dict multi, dict dps, list mpls, IP2AS ip2as, AS2Org as2org, str nodes_file=*, int increment=*);
