from collections import defaultdict
from typing import Dict, Union

from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress

from bdrmapit_parser.graph.construct import Graph
from bdrmapit_parser.graph.node import Interface, Router
from traceparser import ParseResults
from vrf.vrfedge import VRFEdge


class Container:
    def __init__(self, ip2as, as2org, parseres: ParseResults):
        self.ip2as = ip2as
        self.as2org = as2org
        self.parseres = parseres
        self.interfaces: Dict[str, Interface] = {}
        self.routers: Dict[str, Router] = {}
        self.addrs = None
        self.nexthops = None
        self.multi = None
        self.dps = None

    @classmethod
    def load(cls, file, ip2as, as2org):
        results = ParseResults.load(file)
        return cls(ip2as, as2org, results)

    def alladdrs(self):
        return set(self.addrs) | set(self.parseres.echos)

    def filter_addrs(self):
        addrs = set()
        adjs = self.parseres.nextadjs + self.parseres.multiadjs
        pb = Progress(len(adjs), 'Filtering addrs', increment=1000000, callback=lambda: '{:,d}'.format(len(addrs)))
        for (x, y), n in pb.iterator(adjs.items()):
            if n > self.parseres.loopadjs.get((x, y), 0):
                addrs.add(x)
                addrs.add(y)
        self.addrs = addrs

    def create_edges(self):
        nexthops = defaultdict(set)
        kept = 0
        pb = Progress(len(self.parseres.nextadjs), increment=200000, callback=lambda: '{:,d}'.format(kept))
        for (x, y), n in pb.iterator(self.parseres.nextadjs.items()):
            if x != y:
                if n + self.parseres.multiadjs.get((x, y), 0) > self.parseres.loopadjs.get((x, y), 0):
                    xasn = self.ip2as[x]
                    yasn = self.ip2as[y]
                    if xasn == yasn or n > self.parseres.multiadjs.get((x, y), 0):
                        nexthops[x].add(y)
                        kept += 1
        nkept = kept
        mkept = 0
        multi = defaultdict(set)
        pb = Progress(len(self.parseres.multiadjs), increment=200000, callback=lambda: 'N {:,d} M {:,d}'.format(nkept, mkept))
        for (x, y), n in pb.iterator(self.parseres.multiadjs.items()):
            if x != y:
                if n + self.parseres.nextadjs.get((x, y), 0) > self.parseres.loopadjs.get((x, y), 0):
                    xasn = self.ip2as[x]
                    yasn = self.ip2as[y]
                    if xasn == yasn:
                        nexthops[x].add(y)
                        nkept += 1
                    elif x not in nexthops:
                        multi[x].add(y)
                        mkept += 1
        nexthops.default_factory = None
        multi.default_factory = None
        self.nexthops = nexthops
        self.multi = multi

    def create_dps(self):
        dps = defaultdict(set)
        pb = Progress(len(self.parseres.dps), 'Creating dest pairs', increment=1000000)
        for addr, asn in pb.iterator(self.parseres.dps):
            if asn > 0:
                dps[addr].add(asn)
        dps.default_factory = None
        self.dps = dps

    def create_node(self, addr, router: Router):
        """
        Create new interface node and assign it to router.
        :param addr: address of new interface node
        :param router: router node representing the interface's router
        """
        asn = self.ip2as.asn(addr)
        # Make sure address is not from private address space
        if asn >= 0 or asn <= -100:
            # Create interface
            interface = Interface(addr, asn, self.as2org[asn])
            self.interfaces[addr] = interface
            interface.router = router
            # Add interface to router
            router.interfaces.append(interface)
            self.routers[router.name] = router
            # interface.echo = echo
            # interface.cycle = cycle

    def create_nodes(self, nodes_file, increment=100000):
        """
        Create router nodes based on alias resolution.
        :param nodes_file: filename containing alias resolution groupings in CAIDA format
        :param increment: increment for status
        """
        taddrs = self.addrs
        pb = Progress(message='Creating nodes', increment=increment, callback=lambda: 'Routers {:,d} Interfaces {:,d}'.format(len(self.routers), len(self.interfaces)))
        with File2(nodes_file, 'rt') as f:
            for line in pb.iterator(f):
                if line[0] != '#':
                    _, nid, *naddrs = line.split()
                    if not any(addr in taddrs for addr in naddrs):
                        continue
                    nid = nid[:-1]
                    router = Router(nid)
                    self.routers[router.name] = router
                    for addr in naddrs:
                        self.create_node(addr, router)

    def create_remaining(self, aliases: bool, increment=100000):
        """
        Create router nodes for any interfaces not seen in the alias resolution dataset, or when there is not alias resolution dataset.
        :param aliases: flag to indicate if alias resoultion was used
        :param increment: increment for status
        """
        pb = Progress(len(self.addrs), 'Creating remaining routers and interfaces', increment=increment)
        for addr in pb.iterator(self.addrs):
            if not aliases or addr not in self.interfaces:
                router = Router(addr)
                self.create_node(addr, router)

    @staticmethod
    def add_succ(router: Router, interface: Interface, succ: Union[VRFEdge, Interface]):
        if succ in router.succ:
            origins = router.origins[succ]
            origins.add(interface.asn)
        else:
            router.succ.add(succ)
            router.origins[succ] = {interface.asn}

    @staticmethod
    def add_pred(interface: Interface, prouter: Router):
        predcount = interface.pred.get(prouter, 0)
        interface.pred[prouter] = predcount + 1

    def add_nexthop(self, increment=100000):
        """
        Add nexthop edges.
        :param nexthop: nexthop edges
        :param increment: increment for status
        """
        pb = Progress(len(self.nexthops), 'Adding nexthop edges', increment=increment)
        for addr, edges in pb.iterator(self.nexthops.items()):
            interface = self.interfaces[addr]
            router = interface.router
            router.nexthop = True
            for edge in edges:
                succ = self.interfaces[edge]
                if succ.router != router:
                    self.add_succ(router, interface, succ)
                    self.add_pred(succ, router)

    def add_multi(self, increment=100000):
        """
        Add multiple hop edges.
        :param multi: multiple hop edges
        :param increment: increment for status
        """
        pb = Progress(len(self.multi), 'Adding multihop edges', increment=increment)
        for addr in pb.iterator(self.multi):
            interface = self.interfaces[addr]
            router = interface.router
            if not router.nexthop:
                edges = self.multi[addr]
                for edge in edges:
                    succ = self.interfaces[edge]
                    if succ.router != router:
                        self.add_succ(router, interface, succ)

    def add_dests(self, increment=100000):
        """
        Add destination ASes for each interface and router.
        :param dps: interface to destination mappings
        :param increment: increment for status
        """
        pb = Progress(len(self.dps), 'Adding destination ASes', increment=increment)
        for addr, dests in pb.iterator(self.dps.items()):
            interface = self.interfaces.get(addr)
            if interface is not None:
                interface.dests.update(dests)

    def create_graph(self):
        """
        Create the graph based on the interfaces, routers, and edges.
        :return: the graph
        """
        return Graph(interfaces=self.interfaces, routers=self.routers)

    def reset(self):
        self.interfaces = {}
        self.routers = {}

    def construct(self, nodes_file=None):
        """
        Construct the graph from scratch.
        :param addrs: addresses seen in the dataset
        :param nexthop: nexthop edges
        :param multi: multiple hop edges
        :param dps: interface to destination ASes
        :param nodes_file: alias resolution dataset
        :return: the graph
        """
        self.filter_addrs()
        self.create_edges()
        self.create_dps()
        if nodes_file is not None:
            self.create_nodes(nodes_file=nodes_file)
        self.create_remaining(nodes_file is not None)
        self.add_nexthop()
        self.add_multi()
        self.add_dests()
        return self.create_graph()
