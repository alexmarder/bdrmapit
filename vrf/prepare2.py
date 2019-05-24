import pickle
from collections import defaultdict

from deprecated import deprecated
from traceutils.as2org.as2org import AS2Org
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS

from algorithm.parse_results_container import Container


class VRFPrep(Container):
    def __init__(self, ip2as: IP2AS, as2org: AS2Org, vrfinfo=None, nexthop=None, multi=None, **kwargs):
        super().__init__(ip2as, as2org, **kwargs)
        if vrfinfo:
            self.bspace = vrfinfo['middle']
            self.lasts = vrfinfo['last']
        else:
            self.bspace = None
            self.lasts = None
        self.ip2as = ip2as
        self.original_nexthop = nexthop
        self.original_multi = multi
        self.bnext = None
        self.anext = None
        self.bmulti = None
        self.amulti = None
        self.prune = None

    def load_vrfinfo(self, filename):
        with open(filename, 'rb') as f:
            vrfinfo = pickle.load(f)
        self.bspace = vrfinfo['middle']
        self.lasts = vrfinfo['last']

    def mark_vrfs(self, triplets):
        self.bnext = defaultdict(set)
        self.anext = defaultdict(set)
        self.bmulti = defaultdict(set)
        self.amulti = defaultdict(set)
        self.prune = defaultdict(set)
        pb = Progress(len(triplets['triplets']), 'Test', increment=500000, callback=lambda: '{:,d}'.format(len(self.prune)))
        for w, x, y in pb.iterator(triplets['triplets']):
            a, b, c = None, None, None
            if x in self.bspace:
                if not w or not self.bspace[x] or self.ip2as[w] in self.bspace[x]:
                    a, b, c = w, x, y
            if x in self.lasts:
                a, b = w, x
            if y in self.lasts:
                a, b = x, y
            if a and b:
                if a in self.original_nexthop and b in self.original_nexthop[a]:
                    bedges = self.bnext
                    aedges = self.anext
                else:
                    bedges = self.bmulti
                    aedges = self.amulti
                if a:
                    self.prune[a].add(b)
                    bedges[a].add(b)
                    bedges[b].add(a)
                if c:
                    self.prune[b].add(c)
                    aedges[b].add(c)
                    aedges[c].add(b)

    def remove_vrfs(self, edges):
        nexthop = {}
        pb = Progress(len(edges), 'Removing forwarding address edges', increment=500000,
                      callback=lambda: '{:,d}'.format(len(nexthop)))
        for x, succ in pb.iterator(edges.items()):
            if x in self.prune:
                newsucc = [y for y in succ if y not in self.prune[x]]
                if newsucc:
                    nexthop[x] = newsucc
            else:
                nexthop[x] = succ
        return nexthop

    def remove_nexthop(self):
        self.nexthop = self.remove_vrfs(self.original_nexthop)

    def remove_multi(self):
        self.multi = self.remove_vrfs(self.original_multi)

    def add_nexthop_forwarding(self, increment=100000):
        """
        Add nexthop forwarding edges.
        :param nexthop: nexthop forwarding edges
        :param increment: increment for status
        """
        pb = Progress(len(self.bnext), 'Adding nexthop forwarding edges', increment=increment)
        for addr, edges in pb.iterator(self.bnext.items()):
            if addr not in self.interfaces:
                continue
            interface = self.interfaces[addr]
            router = interface.router
            if router.succ:
                continue
            router.nexthop = True
            router.vrf = True
            for edge in edges:
                if edge not in self.interfaces:
                    continue
                succ = self.interfaces[edge].router
                self.add_succ(router, interface, succ)

    def add_pred_forwarding(self, increment=100000):
        """
        Add backward forwarding edges.
        :param pedges: backward forwarding edges
        :param increment: increment for status
        """
        pb = Progress(len(self.anext), 'Adding forwarding backward edges', increment=increment)
        for addr, edges in pb.iterator(self.anext.items()):
            if addr not in self.interfaces:
                continue
            interface = self.interfaces[addr]
            if interface.pred:
                continue
            for edge in edges:
                if edge not in self.interfaces:
                    continue
                prouter = self.interfaces[edge].router
                self.add_pred(interface, prouter)

    def add_multi_forwarding(self, increment=100000):
        """
        Add multiple hop forwarding edges.
        :param multi: multiple hop edges
        :param increment: increment for status
        """
        pb = Progress(len(self.bmulti), 'Adding multihop forwarding edges', increment=increment)
        for addr in pb.iterator(self.bmulti):
            if addr not in self.interfaces:
                continue
            interface = self.interfaces[addr]
            router = interface.router
            if router.nexthop or router.succ:
                continue
            router.vrf = True
            edges = self.bmulti[addr]
            for edge in edges:
                if edge not in self.interfaces:
                    continue
                succ = self.interfaces[edge].router
                self.add_succ(router, interface, succ)

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
        if nodes_file is not None:
            self.create_nodes(nodes_file=nodes_file)
        self.create_remaining(nodes_file is not None)
        # self.note_mpls()
        self.add_nexthop()
        self.add_nexthop_forwarding()
        self.add_pred_forwarding()
        self.add_multi()
        self.add_multi_forwarding()
        self.add_dests()
        return self.create_graph()
