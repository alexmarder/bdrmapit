from typing import Dict, Union

from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress

from bdrmapit.graph.construct import Graph
from bdrmapit.graph.node import Router, Interface
from deprecated import deprecated

from bdrmapit.vrf.prepare import VRFPrep


class GraphConstructor:
    def __init__(self, container, ip2as, as2org):
        self.container = container
        self.ip2as = ip2as
        self.as2org = as2org
        self.interfaces: Dict[str, Interface] = {}
        self.routers: Dict[str, Router] = {}

    def create_node(self, addr, router: Router):
        """
        Create new interface node and assign it to router.
        :param addr: address of new interface node
        :param router: router node representing the interface's router
        """
        asn = self.ip2as.asn(addr)
        # Make sure address is not from private address space
        if asn > 0 or asn <= -100:
            # Create interface
            interface = Interface(addr, asn, self.as2org[asn])
            self.interfaces[addr] = interface
            interface.router = router
            # Add interface to router
            router.interfaces.append(interface)
            self.routers[router.name] = router

    def create_nodes(self, nodes_file, increment=100000):
        """
        Create router nodes based on alias resolution.
        :param nodes_file: filename containing alias resolution groupings in CAIDA format
        :param increment: increment for status
        """
        pb = Progress(message='Creating nodes', increment=increment)
        with File2(nodes_file, 'rt') as f:
            for line in pb.iterator(f):
                if line[0] != '#':
                    _, nid, *naddrs = line.split()
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
        pb = Progress(len(self.container.addrs), 'Creating remaining routers and interfaces', increment=increment)
        for addr in pb.iterator(self.container.addrs):
            if not aliases or addr not in self.interfaces:
                router = Router(addr)
                self.create_node(addr, router)

    @deprecated
    def note_mpls(self, increment=100000):
        """
        Note MPLS interfaces.
        :param mpls: MPLS interface addresses
        :param increment: increment for status
        """
        pb = Progress(len(self.container.mpls), 'Noting MPLS interfaces', increment=increment)
        for addr in pb.iterator(self.container.mpls):
            interface = self.interfaces[addr]
            interface.mpls = True

    @staticmethod
    def add_succ(router: Router, interface: Interface, succ: Union[Router, Interface]):
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
        pb = Progress(len(self.container.nexthop), 'Adding nexthop edges', increment=increment)
        for addr, edges in pb.iterator(self.container.nexthop.items()):
            interface = self.interfaces[addr]
            router = interface.router
            router.nexthop = True
            for edge in edges:
                succ = self.interfaces[edge]
                self.add_succ(router, interface, succ)
                self.add_pred(succ, router)

    def add_nexthop_forwarding(self, increment=100000):
        """
        Add nexthop forwarding edges.
        :param nexthop: nexthop forwarding edges
        :param increment: increment for status
        """
        pb = Progress(len(self.container.bnext), 'Adding nexthop forwarding edges', increment=increment)
        for addr, edges in pb.iterator(self.container.bnext.items()):
            interface = self.interfaces[addr]
            router = interface.router
            if router.succ:
                continue
            router.nexthop = True
            router.vrf = True
            for edge in edges:
                succ = self.interfaces[edge].router
                self.add_succ(router, interface, succ)

    def add_pred_forwarding(self, increment=100000):
        """
        Add backward forwarding edges.
        :param pedges: backward forwarding edges
        :param increment: increment for status
        """
        pb = Progress(len(self.container.anext), 'Adding forwarding backward edges', increment=increment)
        for addr, edges in pb.iterator(self.container.anext.items()):
            interface = self.interfaces[addr]
            if interface.pred:
                continue
            for edge in edges:
                prouter = self.interfaces[edge].router
                self.add_pred(interface, prouter)

    def add_multi(self, increment=100000):
        """
        Add multiple hop edges.
        :param multi: multiple hop edges
        :param increment: increment for status
        """
        pb = Progress(len(self.container.multi), 'Adding multihop edges', increment=increment)
        for addr in pb.iterator(self.container.multi):
            interface = self.interfaces[addr]
            router = interface.router
            if not router.nexthop:
                edges = multi[addr]
                for edge in edges:
                    succ = self.interfaces[edge]
                    self.add_succ(router, interface, succ)

    def add_multi_forwarding(self, increment=100000):
        """
        Add multiple hop forwarding edges.
        :param multi: multiple hop edges
        :param increment: increment for status
        """
        pb = Progress(len(self.container.bmulti), 'Adding multihop forwarding edges', increment=increment)
        for addr in pb.iterator(self.container.bmulti):
            interface = self.interfaces[addr]
            router = interface.router
            if router.nexthop or router.succ:
                continue
            router.vrf = True
            edges = multi[addr]
            for edge in edges:
                succ = self.interfaces[edge].router
                self.add_succ(router, interface, succ)

    def add_dests(self, dps, increment=100000):
        """
        Add destination ASes for each interface and router.
        :param dps: interface to destination mappings
        :param increment: increment for status
        """
        pb = Progress(len(dps), 'Adding destination ASes', increment=increment)
        for addr, dests in pb.iterator(dps.items()):
            interface = self.interfaces[addr]
            interface.dests.update(dests)

    def create_graph(self):
        """
        Create the graph based on the interfaces, routers, and edges.
        :return: the graph
        """
        return Graph(interfaces=self.interfaces, routers=self.routers)

    def construct(self, addrs, nexthop, multi, dps, nodes_file=None, vrfprep: VRFPrep = None):
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
        self.create_remaining(addrs, nodes_file is not None)
        self.note_mpls()
        self.add_nexthop(nexthop)
        if vrfprep is not None:
            pass
        self.add_multi(multi)
        self.add_dests(dps)
        return self.create_graph()
