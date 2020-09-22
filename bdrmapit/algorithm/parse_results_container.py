import pickle
from typing import Dict, Union

from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress

from bdrmapit.bdrmapit_parser import Graph
from bdrmapit.bdrmapit_parser import Interface, Router
from bdrmapit.vrf.vrfedge import VRFEdge


class Container:
    def __init__(self, ip2as, as2org, addrs=None, nexthop=None, multi=None, dps=None, mpls=None, spoofing=None, echos=None, cycles=None):
        self.ip2as = ip2as
        self.as2org = as2org
        self.addrs = addrs
        self.nexthop = nexthop
        self.multi = multi
        self.dps = dps
        self.mpls = mpls
        self.spoofing = spoofing
        self.echos = echos
        self.cycles = cycles
        self.interfaces: Dict[str, Interface] = {}
        self.routers: Dict[str, Router] = {}

    @classmethod
    def load(cls, filename, ip2as, as2org):
        with open(filename, 'rb') as f:
            results = pickle.load(f)
        return cls(ip2as, as2org, **results)

    def alladdrs(self):
        return set(self.addrs) | set(self.echos)

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
        taddrs = set(self.addrs)
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
        :param addrs: addresses included in the graph
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
        pb = Progress(len(self.nexthop), 'Adding nexthop edges', increment=increment)
        for addr, edges in pb.iterator(self.nexthop.items()):
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

    def add_echos(self, increment=1000000):
        echos = 0
        pb = Progress(len(self.echos), 'Adding and marking echos', increment=increment, callback=lambda: '{:,d}'.format(echos))
        for addr in pb.iterator(self.echos):
            if addr in self.interfaces:
                interface = self.interfaces[addr]
                if not interface.dests:
                    interface.echo = True
                    # if all(i.echo for i in interface.router.interfaces):
                    #     interface.router.echo = True
            else:
                router = Router(addr)
                # router.echo = True
                self.create_node(addr, router)
                self.interfaces[addr].echo = True

    def add_cycles(self, increment=1000000):
        echos = 0
        pb = Progress(len(self.cycles), 'Adding and marking cycles', increment=increment, callback=lambda: '{:,d}'.format(echos))
        for addr in pb.iterator(self.echos):
            if addr in self.interfaces:
                interface = self.interfaces[addr]
                if not interface.dests:
                    interface.cycle = True
                    if all(i.cycle for i in interface.router.interfaces):
                        interface.router.echo = True
            else:
                router = Router(addr)
                router.cycle = True
                self.create_node(addr, router, cycle=True)

    def construct(self, nodes_file=None, echos=False, cycles=False):
        """
        Construct the graph from scratch.
        :param addrs: addresses seen in the dataset
        :param nexthop: nexthop edges
        :param multi: multiple hop edges
        :param dps: interface to destination ASes
        :param nodes_file: alias resolution dataset
        :return: the graph
        """
        if nodes_file is not None:
            self.create_nodes(nodes_file=nodes_file)
        self.create_remaining(nodes_file is not None)
        self.add_nexthop()
        self.add_multi()
        self.add_dests()
        if echos:
            self.add_echos()
        if cycles:
            self.add_cycles()
        return self.create_graph()
