cimport cython
from traceutils.as2org.as2org cimport AS2Org
from traceutils.file2.file2 cimport File2
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as cimport IP2AS

from bdrmapit_parser.graph.node cimport Interface, Router


cdef class Graph:
    def __init__(self, dict interfaces=None, dict routers=None):
        if interfaces is None:
            self.interfaces = {}
        else:
            self.interfaces = interfaces
        if routers is None:
            self.routers = {}
        else:
            self.routers = routers


# @cython.nonecheck(False)
# @cython.overflowcheck(False)
cpdef Graph construct_graph(list addrs, dict nexthop, dict multi, dict dps, list mpls, IP2AS ip2as, AS2Org as2org, str nodes_file=None, int increment=100000):
    cdef dict interfaces = {}, routers = {}
    cdef str addr, edge, nid
    cdef int asn, i, predcount
    cdef Interface interface, succ
    cdef Router router
    cdef list edges, dests, naddrs
    cdef set origins

    interfaces = {}
    routers = {}
    if nodes_file is not None:
        pb = Progress(message='Creating nodes', increment=increment)
        with File2(nodes_file, 'rt') as f:
            for line in pb.iterator(f):
                if line[0] != '#':
                    _, nid, *naddrs = line.split()
                    nid = nid[:-1]
                    router = Router(nid)
                    routers[router.name] = router
                    for addr in naddrs:
                        asn = ip2as.asn(addr)
                        if asn > 0 or asn <= -100:
                            interface = Interface(addr, asn, as2org[asn])
                            interfaces[addr] = interface
                            interface.router = router
                            router.interfaces.append(interface)
                            interface.router = router
                            router.interfaces.append(interface)
                            routers[router.name] = router
    pb = Progress(len(addrs), 'Creating remaining routers and interfaces', increment=increment)
    for addr in pb.iterator(addrs):
        if nodes_file is None or addr not in interfaces:
            asn = ip2as.asn(addr)
            interface = Interface(addr, asn, as2org[asn])
            interfaces[addr] = interface
            router = Router(interface.addr)
            interface.router = router
            router.interfaces.append(interface)
            routers[router.name] = router
    pb = Progress(len(mpls), 'Noting MPLS interfaces', increment=increment)
    for addr in pb.iterator(mpls):
        interface = interfaces[addr]
        interface.mpls = True
    # for interface in interfaces.values():
    #     if not interface.router:
    #         router = Router(interface.addr)
    #         interface.router = router
    #         router.interfaces.append(interface)
    #         routers[router.name] = router
    pb = Progress(len(nexthop), 'Adding nexthop edges', increment=increment)
    for addr, edges in pb.iterator(nexthop.items()):
        interface = interfaces[addr]
        router = interface.router
        router.nexthop = True
        for i in range(len(edges)):
            edge = edges[i]
            succ = interfaces[edge]
            if succ in router.succ:
                origins = router.origins[succ]
                origins.add(interface.asn)
            else:
                router.succ.add(succ)
                router.origins[succ] = {interface.asn}
            predcount = succ.pred.get(router, 0)
            succ.pred[router] = predcount + 1
    pb = Progress(len(multi), 'Adding multihop edges', increment=increment)
    for addr in pb.iterator(multi):
        interface = interfaces[addr]
        router = interface.router
        if not router.nexthop:
            edges = multi[addr]
            for edge in edges:
                succ = interfaces[edge]
                if succ in router.succ:
                    router.origins[succ].add(interface.asn)
                else:
                    router.succ.add(succ)
                    router.origins[succ] = {interface.asn}
    pb = Progress(len(dps), 'Adding destination ASes', increment=increment)
    for addr, dests in pb.iterator(dps.items()):
        interface = interfaces[addr]
        interface.dests.update(dests)
    return Graph(interfaces=interfaces, routers=routers)

    # for i in range(len(addrs)):
    #     addr = addrs[i]
    #     asn = ip2as.asn(addr)
    #     interface = Interface(addr, asn, as2org[asn])
    #     interfaces[addr] = interface
    # for addr in mpls:
    #     interface = interfaces[addr]
    #     interface.mpls = True
    # for interface in interfaces.values():
    #     if not interface.router:
    #         router = Router(interface.addr)
    #         interface.router = router
    #         router.interfaces.append(interface)
    #         routers[router.name] = router
    # for addr, edges in nexthop.items():
    #     interface = interfaces[addr]
    #     router = interface.router
    #     router.nexthop = True
    #     for i in range(len(edges)):
    #         edge = edges[i]
    #         succ = interfaces[edge]
    #         if succ in router.succ:
    #             origins = router.origins[succ]
    #             origins.add(interface.asn)
    #         else:
    #             router.succ.add(succ)
    #             router.origins[succ] = {interface.asn}
    #         predcount = succ.pred.get(router, 0)
    #         succ.pred[router] = predcount + 1
    # for addr in multi:
    #     interface = interfaces[addr]
    #     router = interface.router
    #     if not router.nexthop:
    #         edges = multi[addr]
    #         for edge in edges:
    #             succ = interfaces[edge]
    #             if succ in router.succ:
    #                 router.origins[succ].add(interface.asn)
    #             else:
    #                 router.succ.add(succ)
    #                 router.origins[succ] = {interface.asn}
    # for addr, dests in dps.items():
    #     interface = interfaces[addr]
    #     interface.dests.update(dests)
    # return Graph(interfaces=interfaces, routers=routers)
