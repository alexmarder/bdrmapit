import sys
from collections import Counter
from typing import Collection, List, Dict

from traceutils.as2org.as2org import AS2Org
from traceutils.bgp.bgp import BGP
from traceutils.progress.bar import Progress
from traceutils.utils.utils import max_num, peek

from bdrmapit.bdrmapit_parser import Updates
from bdrmapit.bdrmapit_parser import Graph
from bdrmapit.bdrmapit_parser import Router, Interface


DEBUG = False

NOTIMPLEMENTED = 0
NODEST = 1
MODIFIED = 3
SINGLE = 4
SINGLE_MODIFIED = 5
HEAPED = 6
HEAPED_MODIFIED = 7
MISSING_NOINTER = 10
MISSING_INTER = 9

REALLOCATED_PREFIX = 500
REALLOCATED_DEST = 1000
SINGLE_SUCC_ORIGIN = 10
SINGLE_SUCC_4 = 11
SUCC_ORIGIN_INTER = 12
SUCC_ORIGIN_CUST = 13
REMAINING_4 = 14
IUPDATE = 15
ALLPEER_SUCC = 16
ALLPEER_ORIGIN = 17
IASN_SUCC_HALF = 18
ALLRELS = 19
VOTE_SINGLE = 50
VOTE_TIE = 70
SINGLE_SUCC_RASN = 15
HIDDEN_INTER = 100
HIDDEN_NOINTER = 200


class Debug:

    def __init__(self):
        self.old = DEBUG

    def __enter__(self):
        global DEBUG
        DEBUG = True

    def __exit__(self, exc_type, exc_val, exc_tb):
        global DEBUG
        DEBUG = self.old
        return False


class Bdrmapit:

    def __init__(self, graph: Graph, as2org: AS2Org, bgp: BGP):
        self.graph = graph
        self.as2org = as2org
        self.bgp = bgp
        self.rupdates = Updates()
        self.iupdates = Updates()
        self.routers_succ: List[Router] = []
        self.lasthops: List[Router] = []
        for router in graph.routers.values():
            if router.succ:
                self.routers_succ.append(router)
            else:
                self.lasthops.append(router)
        self.interfaces_pred: List[Interface] = [i for i in graph.interfaces.values() if i.pred]
        self.previous_updates = []

    def annotate_router(self, router: Router):
        isucc: Interface
        if DEBUG:
            print('Nexthop: {}'.format(router.nexthop))
        asns = Counter(i.asn for i in router.interfaces if i.asn > 0)
        if DEBUG: print('IASNS: {}'.format(asns))
        for isucc in router.succ:
            if DEBUG: print('Succ: {}'.format(isucc))
            iupdate = self.iupdates[isucc]
            rupdate = self.rupdates[isucc.router]
            if DEBUG:
                print('\tIUPDATE: {}'.format(iupdate))
                print('\tRUPDATE: {}'.format(rupdate))
            if iupdate and iupdate.asn > 0:
                if not rupdate:
                    asn = isucc.asn
                else:
                    if rupdate.asn > 0 and isucc.org == rupdate.org:
                        asn = iupdate.asn
                    else:
                        asn = isucc.asn
            else:
                asn = isucc.asn
            if asn > 0:
                asns[asn] += 1
        if not asns:
            return 0
        selections = max_num(asns, key=lambda x: asns[x])
        if len(selections) == 1:
            return selections[0]
        return router.interfaces[0].asn

    def annotate_routers(self, routers: Collection[Router], increment=100000):
        pb = Progress(len(routers), 'Annotating routers', increment=increment)
        for router in pb.iterator(routers):
            asn = self.annotate_router(router)
            self.rupdates.add_update(router, asn, self.as2org[asn], 1)

    def annotate_interface(self, interface: Interface):
        edges: Dict[Router, int] = interface.pred
        asns = Counter()
        if interface.asn > 0:
            asns[interface.asn] += 1
        if DEBUG: print('IASN: {}'.format(asns))
        for rpred in edges:
            rasn = self.rupdates.asn(rpred)
            if DEBUG:
                print('Pred={addr:} RASN={rasn:} {num:}'.format(addr=rpred.name, rasn=rasn, num=len(rpred.succ)))
            if rasn > 0:
                asns[rasn] += 1
        selections = max_num(asns, key=lambda x: asns[x])
        if len(selections) == 1:
            return selections[0], len(edges)
        return interface.asn, 0

    def annotate_interfaces(self, interfaces: Collection[Interface]):
        pb = Progress(len(interfaces), 'Adding links', increment=100000)
        for interface in pb.iterator(interfaces):
            if interface.asn >= 0:
                asn, utype = self.annotate_interface(interface)
                self.iupdates.add_update(interface, asn, self.as2org[asn], utype)

    def annotate_stubs(self, routers: Collection[Router]):
        pb = Progress(len(routers), 'Stub Heuristic', increment=100000)
        for router in pb.iterator(routers):
            if len(router.succ) == 1:
                interface = router.interfaces[0]
                iupdate = self.iupdates[interface]
                if iupdate and iupdate.utype > 1:
                    if interface.org != iupdate.org:
                        continue
                isucc = peek(router.succ)
                iupdate = self.iupdates[isucc]
                if iupdate and iupdate.utype > 1:
                    # if isucc.org != iupdate.org:
                        continue
                rupdate = self.rupdates[isucc.router]
                if rupdate:
                    if isucc.org != rupdate.org:
                        continue
                conesize = self.bgp.conesize[isucc.asn]
                if conesize < 5 and conesize < self.bgp.conesize[router.interfaces[0].asn]:
                    self.rupdates.add_update_direct(router, isucc.asn, isucc.org, 2)

    def annotate_lasthops(self, routers: List[Router]):
        pb = Progress(len(routers), increment=1000000)
        for router in pb.iterator(routers):
            interface = router.interfaces[0]
            self.rupdates.add_update_direct(router, interface.asn, interface.org, 0)

    def graph_refinement(self, routers: List[Router], interfaces: List[Interface], iterations=-1):
        iteration = 0
        while iterations < 0 or iteration < iterations:
            Progress.message('********** Iteration {:,d} **********'.format(iteration), file=sys.stderr)
            self.annotate_routers(routers)
            self.rupdates.advance()
            self.annotate_interfaces(interfaces)
            self.iupdates.advance()
            ru = dict(self.rupdates)
            iu = dict(self.iupdates)
            if (ru, iu) in self.previous_updates:
                break
            self.previous_updates.append((ru, iu))
            iteration += 1
