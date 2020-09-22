import pickle
from collections import defaultdict
from typing import Dict, Optional

from traceutils.as2org.as2org import AS2Org
from traceutils.file2 import fopen
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS
from traceutils.utils.net import otherside

from bdrmapit.container.container import Container
from scripts.traceparser import ParseResults
from bdrmapit.vrf.vrfedge import VRFEdge, VType


class VRFPrep(Container):
    def __init__(self, ip2as: IP2AS, as2org: AS2Org, parseres: ParseResults, vrfinfo=None):
        super().__init__(ip2as, as2org, parseres)
        if vrfinfo:
            self.middle = vrfinfo['middle']
            self.last = vrfinfo['last']
        else:
            self.middle = None
            self.last = None
        self.ip2as = ip2as
        self.create_edges()
        self.original_nexthop = dict(self.nexthops)
        self.original_multi = dict(self.multi)
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
        # self.middle = {x: asns for x, asns in self.middle.items() if asns != {self.ip2as[x]}}

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
            if a == '17.1.154.14' or b == '17.1.154.14':
                print(a, b, c)
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

        pb = Progress(message='Marking VRF edges', increment=500000, callback=lambda: '{:,d}'.format(len(self.prune)))
        print(self.middle.get('2001:504:0:1::6939:1'))
        with fopen(triplets) as f:
            for line in pb.iterator(f):
                w, x, y = line.split()
                if x in self.middle:
                    # if x == '2001:504:0:1::6939:1':
                    #     print(w, x, y)
                    if not w:
                        if None in self.middle[x]:
                            mark(x, y)
                    else:
                        if self.ip2as[w] in self.middle[x]:
                            mark(w, x, y)
                if y in self.last:
                    if not w:
                        if None not in self.last[y]:
                            mark(x, y)
                    else:
                        pasns = self.last[y]
                        if self.ip2as[x] not in pasns:
                            mark(x, y)
        self.bnext = self.merge_edgetypes(toforward_next, forwarding_next)
        self.bmulti = self.merge_edgetypes(toforward_multi, forwarding_multi)

    def remove_vrfs(self, edges, debug=None):
        nexthop = {}
        removed = set()
        pb = Progress(len(edges), 'Removing forwarding address edges', increment=500000, callback=lambda: 'K {:,d} R {:,d}'.format(len(nexthop), len(removed)))
        for x, succ in pb.iterator(edges.items()):
            if x == debug:
                print(x, succ, self.prune.get(x))
            if x in self.prune:
                newsucc = succ - self.prune[x]
                # newsucc = [y for y in succ if y not in self.prune[x]]
                if newsucc:
                    nexthop[x] = newsucc
                else:
                    removed.add(x)
            else:
                nexthop[x] = succ
        return nexthop

    def remove_nexthop(self, **kwargs):
        self.nexthops = self.remove_vrfs(self.original_nexthop, **kwargs)

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
        :param skip_exists: don't add vrf edges if normal edges exist
        :param increment: increment for status
        """
        self.add_vrfedges(self.bnext, True, skip_exists=skip_exists, increment=increment)

    def add_pred_forwarding(self, skip_exists=True, increment=100000):
        """
        Add backward forwarding edges.
        :param skip_exists: don't add vrf edges if normal edges exist
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
        :param skip_exists: don't add vrf edges if normal edges exist
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
        :param skip_graph: 
        :param skip_dests: 
        :param skip_nodes: 
        :param skip_exists: 
        :param nodes_file: alias resolution dataset
        :return: the graph
        """

        # self.filter_addrs()
        # self.create_edges()
        # self.create_dps()
        # if nodes_file is not None:
        #     self.create_nodes(nodes_file=nodes_file)
        # self.create_remaining(nodes_file is not None)
        # self.add_nexthop()
        # self.add_multi()
        # self.add_dests()
        # return self.create_graph()
        self.filter_addrs()
        self.create_dps()
        if not skip_nodes:
            if nodes_file is not None:
                self.create_nodes(nodes_file=nodes_file)
            self.create_remaining(nodes_file is not None)
        self.add_nexthop()
        self.add_nexthop_forwarding(skip_exists=skip_exists)
        self.add_pred_forwarding(skip_exists=skip_exists)
        self.add_multi()
        self.add_multi_forwarding(skip_exists=skip_exists)
        if not skip_dests:
            self.add_dests()
        if not skip_graph:
            return self.create_graph()
