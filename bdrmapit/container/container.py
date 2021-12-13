from collections import defaultdict
from itertools import chain
from sys import stderr
from typing import Dict, Union

from traceutils.file2.file2 import fopen
from traceutils.progress.bar import Progress

from bdrmapit.graph.construct import Graph
from bdrmapit.graph.node import Interface, Router
from scripts.traceparser import ParseResults
from bdrmapit.vrf.vrfedge import VRFEdge

import pandas as pd

def construct_graph(ip2as, as2org, filename, remove_edges=None):
    prep = Container.load(ip2as, as2org, filename)
    if remove_edges is not None:
        for x, y in remove_edges:
            if (x, y) in prep.parseres.nextadjs:
                del prep.parseres.nextadjs[x, y]
            if (x, y) in prep.parseres.multiadjs:
                del prep.parseres.multiadjs[x, y]
    return prep.construct(no_echos=True)

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
        self.firstaddrs = None
        self.echos = None

    @classmethod
    def load(cls, ip2as, as2org, *files):
        allresults = None
        for file in files:
            results = ParseResults.load(file)
            if allresults is None:
                allresults = results
            else:
                allresults.update(results)
        return cls(ip2as, as2org, allresults)

    def alladdrs(self):
        return set(self.addrs) | set(self.parseres.echos)

    def filter_addrs(self, loop=True, no_echos=False):
        addrs = set()
        firstaddrs = {addr for _, addr in self.parseres.first}
        adjs = self.parseres.nextadjs + self.parseres.multiadjs
        pb = Progress(len(adjs), 'Filtering addrs', increment=1000000, callback=lambda: '{:,d}'.format(len(addrs)))
        for (x, y), n in pb.iterator(adjs.items()):
            if not loop or n > self.parseres.loopadjs.get((x, y), 0):
                addrs.add(x)
                addrs.add(y)
                firstaddrs.discard(y)
        self.addrs = addrs | firstaddrs
        self.addrs |= {addr for addr, _ in self.parseres.dps}
        if not no_echos:
            self.addrs |= self.parseres.echos
        # self.firstaddrs = {(file, addr) for file, addr in self.parseres.first if addr in firstaddrs}
        Progress.message('Total addrs: {:,d}'.format(len(self.addrs)), file=stderr)

    def set_echos(self):
        pass

    def create_edges(self, loop=True):
        nexthops = defaultdict(set)
        kept = 0
        pb = Progress(len(self.parseres.nextadjs), increment=200000, callback=lambda: '{:,d}'.format(kept))
        for (x, y), n in pb.iterator(self.parseres.nextadjs.items()):
            if x != y:
                if not loop or n + self.parseres.multiadjs.get((x, y), 0) > self.parseres.loopadjs.get((x, y), 0):
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
                if not loop or n + self.parseres.nextadjs.get((x, y), 0) > self.parseres.loopadjs.get((x, y), 0):
                    xasn = self.ip2as[x]
                    yasn = self.ip2as[y]
                    if xasn > 0 and yasn > 0 and xasn == yasn:
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

    def create_nodes(self, nodes_file, no_echos: bool = False, increment=100000):
        """
        Create router nodes based on alias resolution.
        :param no_echos: ignore echo-only addresses
        :param nodes_file: filename containing alias resolution groupings in CAIDA format
        :param increment: increment for status
        """
        if not no_echos:
            taddrs = self.alladdrs()
        else:
            taddrs = self.addrs
        pb = Progress(message='Creating nodes', increment=increment, callback=lambda: 'Routers {:,d} Interfaces {:,d}'.format(len(self.routers), len(self.interfaces)))
        with fopen(nodes_file, 'rt') as f:
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

    def create_remaining(self, aliases: bool, no_echos: bool = False, increment=100000):
        """
        Create router nodes for any interfaces not seen in the alias resolution dataset, or when there is not alias resolution dataset.
        :param aliases: flag to indicate if alias resoultion was used
        :param increment: increment for status
        """
        if not no_echos:
            taddrs = chain(self.addrs, self.parseres.echos)
            num_addrs = len(self.addrs) + len(self.parseres.echos)
        else:
            taddrs = self.addrs
            num_addrs = len(self.addrs)
        pb = Progress(num_addrs, 'Creating remaining routers and interfaces', increment=increment)
        for addr in pb.iterator(taddrs):
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

    def reset_hints(self):
        for interface in self.interfaces.values():
            interface.hint = 0
            interface.router.hints = None

    def add_hints(self, hints: Dict[str, int]):
        for addr, hint in hints.items():
            if addr in self.interfaces:
                interface = self.interfaces[addr]
                interface.hint = hint
                if not interface.router.hints:
                    interface.router.hints = {hint}
                else:
                    interface.router.hints.add(hint)

    def add_hints_file(self, filename):
        print('Adding hints from {}'.format(filename))
        df = pd.read_csv(filename, sep=r'\s+', index_col=0, names=['addr', 'tasn'])
        hints = dict(df.tasn)
        self.add_hints(hints)

    def reset(self):
        self.interfaces = {}
        self.routers = {}

    def construct(self, nodes_file=None, loop=True, hints_file=None, no_echos=False):
        """
        Construct the graph from scratch.
        :param addrs: addresses seen in the dataset
        :param nexthop: nexthop edges
        :param multi: multiple hop edges
        :param dps: interface to destination ASes
        :param nodes_file: alias resolution dataset
        :return: the graph
        """
        self.filter_addrs(loop=loop, no_echos=no_echos)
        self.create_edges(loop=loop)
        self.create_dps()
        if nodes_file is not None:
            self.create_nodes(nodes_file=nodes_file, no_echos=no_echos)
        self.create_remaining(nodes_file is not None, no_echos=no_echos)
        self.add_nexthop()
        self.add_multi()
        self.add_dests()
        if hints_file is not None:
            self.add_hints_file(hints_file)
        return self.create_graph()
