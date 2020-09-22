import pickle
from collections import defaultdict
from typing import Dict, Optional

from traceutils.as2org.as2org import AS2Org
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS
from traceutils.utils.net import otherside

from bdrmapit.algorithm.parse_results_container import Container
from bdrmapit.vrf.vrfedge import VRFEdge, VType


class VRFPrep(Container):
    def __init__(self, ip2as: IP2AS, as2org: AS2Org, vrfinfo=None, nexthop=None, multi=None, **kwargs):
        super().__init__(ip2as, as2org, **kwargs)
        if vrfinfo:
            self.middle = vrfinfo['middle']
            self.last = vrfinfo['last']
        else:
            self.middle = None
            self.last = None
        self.ip2as = ip2as
        self.original_nexthop = nexthop
        self.original_multi = multi
        self.bnext: Optional[Dict[str, Dict[str, VType]]] = None
        self.anext = None
        self.bmulti: Optional[Dict[str, Dict[str, VType]]] = None
        self.amulti = None
        self.prune = None

    def load_vrfinfo(self, filename):
        with open(filename, 'rb') as f:
            vrfinfo = pickle.load(f)
        self.middle = vrfinfo['middle']
        self.last = vrfinfo['last']

    def merge_edgetypes(self, toforward, forwarding):
        bedges = defaultdict(dict)
        keys = toforward.keys() | forwarding.keys()
        for addr in keys:
            set1 = toforward[addr] if addr in toforward else set()
            set2 = forwarding[addr] if addr in forwarding else set()
            for succ in set1 - set2:
                bedges[addr][succ] = VType.toforward
            for succ in set2 - set1:
                bedges[addr][succ] = VType.forwarding
            for succ in set1 & set2:
                bedges[addr][succ] = VType.forwarding
        bedges.default_factory = None
        return bedges

    def mark_vrfs(self, triplets):
        toforward_next = defaultdict(set)
        forwarding_next = defaultdict(set)
        self.bnext = defaultdict(dict)
        self.anext = defaultdict(set)
        toforward_multi = defaultdict(set)
        forwarding_multi = defaultdict(set)
        self.bmulti = defaultdict(dict)
        self.amulti = defaultdict(set)
        self.prune = defaultdict(set)

        def mark(a, b, c=None):
            if a in self.original_nexthop and b in self.original_nexthop[a]:
                toforward = toforward_next
                forwarding = forwarding_next
                aedges = self.anext
            else:
                toforward = toforward_multi
                forwarding = forwarding_multi
                aedges = self.amulti
            if a:
                self.prune[a].add(b)
                toforward[a].add(b)
                forwarding[b].add(a)
            if c:
                self.prune[b].add(c)
                aedges[b].add(c)
                aedges[c].add(b)

        pb = Progress(len(triplets), 'Test', increment=500000, callback=lambda: '{:,d}'.format(len(self.prune)))
        for w, x, y in pb.iterator(triplets):
            if x in self.middle:
                if not w:
                    if None in self.middle[x]:
                        mark(x, y)
                else:
                    if self.ip2as[w] in self.middle[x]:
                        mark(w, x, y)
            if y in self.last:
                # if y == '2001:468:f000:2132::1':
                #     print(w, x, y)
                if not w:
                    if None not in self.last[y]:
                        mark(x, y)
                else:
                    pasns = self.last[y]
                    if self.ip2as[x] not in pasns:
                        mark(x, y)
        self.bnext = self.merge_edgetypes(toforward_next, forwarding_next)
        self.bmulti = self.merge_edgetypes(toforward_multi, forwarding_multi)

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

    def add_vrfedges(self, bedges: Dict[str, Dict[str, VType]], nexthop, skip_exists=True, increment=100000):
        etype = 'nexthop' if nexthop else 'multi'
        pb = Progress(len(bedges), 'Adding {} forwarding edges'.format(etype), increment=increment)
        for addr, succs in pb.iterator(bedges.items()):
            if addr not in self.interfaces:
                continue
            interface = self.interfaces[addr]
            router = interface.router
            if not nexthop and router.nexthop:
                continue
            if skip_exists and router.succ:
                continue
            router.nexthop = nexthop
            router.vrf = True
            for succ, vtype in succs.items():
                if succ not in self.interfaces:
                    continue
                srouter = self.interfaces[succ].router
                edge = VRFEdge(srouter, vtype)
                self.add_succ(router, interface, edge)

    def add_nexthop_forwarding(self, skip_exists=True, increment=100000):
        """
        Add nexthop forwarding edges.
        :param nexthop: nexthop forwarding edges
        :param increment: increment for status
        """
        self.add_vrfedges(self.bnext, True, skip_exists=skip_exists, increment=increment)

    def add_pred_forwarding(self, skip_exists=True, increment=100000):
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
            if skip_exists and interface.pred:
                continue
            for edge in edges:
                if edge not in self.interfaces:
                    continue
                try:
                    if otherside(edge, 2) == addr or otherside(edge, 4) == addr:
                        prouter = self.interfaces[edge].router
                        self.add_pred(interface, prouter)
                except:
                    pass

    def add_multi_forwarding(self, skip_exists=True, increment=100000):
        """
        Add multiple hop forwarding edges.
        :param multi: multiple hop edges
        :param increment: increment for status
        """
        self.add_vrfedges(self.bmulti, False, skip_exists=skip_exists, increment=increment)

    def reset(self, keep_nodes=True):
        pb = Progress(len(self.routers), 'Resetting router edges', increment=1000000)
        for router in pb.iterator(self.routers.values()):
            router.succ.clear()
            router.origins.clear()
        pb = Progress(len(self.interfaces), 'Resetting interface edges', increment=1000000)
        for interface in pb.iterator(self.interfaces.values()):
            interface.pred.clear()

    def construct(self, nodes_file=None, skip_exists=True, skip_nodes=False, skip_dests=False, skip_graph=False):
        """
        Construct the graph from scratch.
        :param addrs: addresses seen in the dataset
        :param nexthop: nexthop edges
        :param multi: multiple hop edges
        :param dps: interface to destination ASes
        :param nodes_file: alias resolution dataset
        :return: the graph
        """
        if not skip_nodes:
            if nodes_file is not None:
                self.create_nodes(nodes_file=nodes_file)
            self.create_remaining(nodes_file is not None)
        # self.note_mpls()
        self.add_nexthop()
        self.add_nexthop_forwarding(skip_exists=skip_exists)
        self.add_pred_forwarding(skip_exists=skip_exists)
        self.add_multi()
        self.add_multi_forwarding(skip_exists=skip_exists)
        if not skip_dests:
            self.add_dests()
        # self.add_echos()
        # self.add_cycles()
        if not skip_graph:
            return self.create_graph()
