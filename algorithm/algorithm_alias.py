import sys
from collections import Counter, defaultdict
from typing import Collection, List, Set, Dict, DefaultDict, Union, Tuple, Counter as TCounter

from traceutils.as2org.as2org import AS2Org
from traceutils.bgp.bgp import BGP
from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress
from traceutils.utils.utils import max_num, peek

# from bdrmapit_parser.algorithm.bdrmapit import Bdrmapit
from bdrmapit_parser.algorithm.updates_dict import Updates, UpdatesView
from bdrmapit_parser.graph.construct import Graph
from bdrmapit_parser.graph.node import Router, Interface
import heapq as hq


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
        self.routers_mpls: List[Router] = []
        self.lasthops: List[Router] = []
        self.routers_succ: List[Router] = []
        for router in graph.routers.values():
            if any(i.mpls for i in router.interfaces):
                self.routers_mpls.append(router)
            else:
                if router.succ:
                    self.routers_succ.append(router)
                else:
                    self.lasthops.append(router)
        self.interfaces_pred: List[Interface] = [i for i in graph.interfaces.values() if i.pred and not i.mpls]
        self.previous_updates = []

    def set_dests(self, increment=100000):
        pb = Progress(len(self.graph.interfaces), 'Modifying interface dests', increment=increment)
        for interface in pb.iterator(self.graph.interfaces.values()):
            idests: Set[int] = interface.dests
            if idests:
                orgs = {self.as2org[a] for a in idests}
                if len(orgs) == 2 and interface.asn in idests:
                    if max(idests, key=lambda x: (self.bgp.conesize[x], -x)) == interface.asn:
                        idests.discard(interface.asn)
        pb = Progress(len(self.graph.routers), 'Setting destinations', increment=increment)
        for router in pb.iterator(self.graph.routers.values()):
            for interface in router.interfaces:
                router.dests.update(interface.dests)

    def annotate_mpls(self):
        pb = Progress(len(self.routers_mpls), 'Annotating MPLS routers', increment=100000)
        for router in pb.iterator(self.routers_mpls):
            origins = Counter()
            for interface in router.interfaces:
                if interface.mpls:
                    origins[interface.asn] += 1
            if len(origins) > 1:
                raise Exception('Not sure what to do with multiple origin ASes')
            if len(origins) == 1:
                asn = peek(origins)
                org = self.as2org[asn]
                self.rupdates.add_update_direct(router, asn, org, 2)

    def heaptest(self, rdests: Set[int], interface: Interface):
        heap = []
        for a in rdests:
            hq.heappush(heap, (self.bgp.conesize[a], -a, a))
        original_min = heap[0][-1]
        while heap:
            dest = hq.heappop(heap)[-1]
            if interface.asn == dest or self.bgp.rel(interface.asn, dest):
                return dest
        return original_min

    def annotate_lasthop(self, router: Router):
        if DEBUG: print('Dests: {}'.format(router.dests))
        interfaces = router.interfaces[0]
        iasns = Counter(interface.asn for interface in interfaces)

        # If no destination ASes
        if len(router.dests) == 0 or all(dest <= 0 for dest in router.dests):
            if len(iasns) == 0:
                return peek(iasns), NODEST
            return max(iasns, key=lambda x: (iasns[x], -self.bgp.conesize[x]))

        # Check for single organization
        rorgs = {self.as2org[d] for d in router.dests}
        if len(rorgs) == 1:
            dest = peek(router.dests)
            utype = SINGLE

        # Multiple destination organization
        else:
            if DEBUG: print('IASN: {}'.format(iasn))
            dest = self.heaptest(router.dests, interface)
            utype = HEAPED

        # If the interface AS has no relationship to the selected AS, check for hidden AS
        if iasn > 0 and iasn != dest and not self.bgp.rel(iasn, dest):
            if DEBUG: print('No Rel: {}-{}'.format(iasn, dest))
            intersection = self.bgp.providers[dest] & self.bgp.customers[iasn]
            # Only use intersection AS if it is definitive
            if len(intersection) == 1:
                dest = peek(intersection)
                return dest, MISSING_INTER
            # Otherwise, use the interface AS
            else:
                if DEBUG: print(self.bgp.providers[dest] & self.bgp.peers[iasn])
                return iasn, MISSING_NOINTER
        return dest, utype

    def annotate_lasthops(self):
        ifs = 0
        ds = 0
        pb = Progress(len(self.lasthops), message='Last Hops', increment=100000, callback=lambda: 'Is {:,d} Ds {:,d} Total {:,d}'.format(ifs, ds, ifs+ds))
        for router in pb.iterator(self.lasthops):
            dest, utype = self.annotate_lasthop(router)
            if utype == NODEST:
                ifs += 1
            else:
                ds += 1
            self.rupdates.add_update_direct(router, dest, self.as2org[dest], utype)

    def router_heuristics(self, router: Router, isucc: Interface, iasn: int):
        rsucc: Router = isucc.router
        rsucc_asn = self.rupdates.asn(rsucc)
        succ_asn = self.iupdates.asn(isucc)
        if DEBUG:
            print('\tASN={}, RASN={}, IASN={} VRF={}'.format(isucc.asn, rsucc_asn, succ_asn, router.vrf))

        # If subsequent interface AS has no known origin, use subsequent router AS
        if isucc.asn == 0 or router.vrf:
            return rsucc_asn

        # If subsequent interface is an IXP interface, use interface AS
        if isucc.asn <= -100:
            return iasn if iasn > 0 else -1

        # If subsequent interface AS is the same as the interface AS, use it
        if isucc.asn == iasn:
            return isucc.asn

        # If subsequent router AS is different from the subsequent interface AS
        if rsucc_asn > 0 and rsucc_asn != isucc.asn and isucc.org != self.as2org[iasn]:
            if DEBUG: print('\tThird party: Router={}, RASN={}'.format(rsucc.name, rsucc_asn))
            if iasn == rsucc_asn or self.bgp.rel(iasn, rsucc_asn):
                if DEBUG: print('\tISUCC in Dests: {} in {}'.format(isucc.asn, router.dests))
                if isucc.asn not in router.dests:
                    return rsucc_asn
                elif self.bgp.rel(isucc.asn, rsucc_asn) and not self.bgp.rel(isucc.asn, iasn):
                    return rsucc_asn
        if succ_asn <= 0 or (0 < rsucc_asn != isucc.asn):
            return isucc.asn
        return succ_asn

    def hidden_asn(self, iasn: int, asn: int, utype: int, votes: Dict[int, int]):
        """
        Look for hidden AS between the interface AS and the selected AS.
        """
        intasn: int = None
        # First look for customers of interface AS who are providers of selected AS
        intersection: Set[int] = self.bgp.customers[iasn] & self.bgp.providers[asn]
        # Only use if the intersection is definitive, i.e., a single AS
        if len(intersection) == 1:
            intasn = peek(intersection)
            if DEBUG: print('Hidden: {}'.format(intasn))

        # If there is no intersection, check for provider of interface AS who is customer of selected AS
        elif not intersection:
            intersection = self.bgp.providers[iasn] & self.bgp.customers[asn]
            if len(intersection) == 1:
                intasn = peek(intersection)
                if DEBUG: print('Hidden Reversed: {}'.format(intasn))

        # If a hidden AS was selected
        if intasn is not None:
            interorg = self.as2org[intasn]
            # If the hidden AS is a sibling of an AS which received a vote (interface or subsequent AS),
            #  use the selected AS. I think it suggests the selected AS actually has a relationship.
            if interorg in {self.as2org[vasn] for vasn in votes}:
                return asn, HIDDEN_NOINTER + utype
            return intasn, HIDDEN_INTER + utype

        if DEBUG: print('Missing: {}-{}'.format(iasn, asn))
        # If a sibling of the selected AS has a relationship to the interface AS, use the sibling
        for sibasn in self.as2org.siblings[asn]:
            if self.bgp.rel(iasn, sibasn):
                return sibasn, 200000 + utype

        # If a sibling of the interface AS has a relationship to the selected AS, use the selected AS
        for sibasn in self.as2org.siblings[iasn]:
            if self.bgp.rel(sibasn, asn):
                return asn, 300000 + utype
                # return sibasn, 300000 + utype
        return iasn, HIDDEN_NOINTER + utype

    def annotate_router(self, router: Router):
        isucc: Interface
        utype: int = 0

        # All routers have only a single interface -- no aliases
        iasn: int = router.interfaces[0].asn
        if DEBUG:
            print('IASN: {}'.format(iasn))
            print('Edges={}, NH={}'.format(len(router.succ), router.nexthop))
            print('MPLS?: {}'.format(any(i.mpls for i in router.interfaces)))

        # utype += reallocated(bdrmapit, router, edges, rupdates, succs, succ_origins)

        # Use heuristics to determine link votes
        succs = Counter()
        for isucc in router.succ:
            if DEBUG: print('Succ={}, ASN={}, Origins={}'.format(isucc.addr, isucc.asn, iasn))
            succ_asn = self.router_heuristics(router, isucc, iasn)
            if DEBUG: print('Heuristic: {}'.format(succ_asn))
            if succ_asn > 0:
                succs[succ_asn] += 1
        if DEBUG: print('Succs: {}'.format(succs))

        # Deal specially with cases where there is only a single subsequent AS
        if len(succs) == 1 or len({self.as2org[sasn] for sasn in succs}) == 1:
            sasn = peek(succs) if len(succs) == 1 else max(succs, key=lambda x: (self.bgp.conesize[x], -x))
            # Subsequent AS = Interface AS
            if sasn == iasn:
                return sasn, utype + SINGLE_SUCC_ORIGIN

            # Subsequent AS is customer of interface AS
            if self.bgp.customer_rel(sasn, iasn):
                if DEBUG: print('Provider: {}->{}'.format(iasn, sasn))
                return sasn, utype + SINGLE_SUCC_4

            # No relationship between interface AS and subsequent AS
            if not self.bgp.rel(iasn, sasn) and self.bgp.conesize[iasn] > self.bgp.conesize[sasn]:
                return self.hidden_asn(iasn, sasn, utype, {iasn: 1})

            # Not sure what I'm trying to do here
            for isucc in router.succ:
                supdate = self.iupdates[isucc]
                if supdate:
                    sasn2 = supdate.asn
                    itype = supdate.utype
                    rasn = self.rupdates.asn(isucc.router)
                    if sasn2 == sasn and ((rasn == sasn and itype == 1) or rasn != sasn):
                        return sasn, utype + IUPDATE

            # Or here
            rasns = set()
            for isucc in router.succ:
                rasn = self.rupdates.asn(isucc.router)
                rasns.add(rasn if rasn > 0 else sasn)
            if DEBUG: print('RASNS={}, SASN={}'.format(rasns, sasn))
            if sasn not in rasns:
                return sasn, utype + SINGLE_SUCC_RASN

            # Check if interface AS is customer of subsequent AS
            sasn = peek(succs)
            if self.bgp.customer_rel(sasn, iasn):
                return sasn, utype + REMAINING_4

        # Create votes counter and add interface AS
        votes = Counter(succs)
        if iasn > 0:
            votes[iasn] += 1
        if DEBUG: print('Votes: {}'.format(votes))
        if not votes:
            return -1, -1

        # More than 1 subsequent AS
        if len(succs) > 1:
            noiasn = Counter(succs)
            noiasn[iasn] -= 1
            if sum(1 for v in noiasn.values() if v > 0) > 1 and all(v < 2 for v in noiasn.values()):
                if all(iasn == sasn or self.as2org[iasn] == self.as2org[sasn] or self.bgp.rel(iasn, sasn)
                       for sasn in succs):
                    return iasn, 1000000
            if iasn not in succs:
                if all(self.bgp.peer_rel(iasn, sasn) for sasn in succs):
                    if votes[iasn] > max(votes.values()) / 2:
                        return iasn, utype + ALLPEER_SUCC
            if iasn in succs:
                if all(self.bgp.peer_rel(iasn, sasn) or self.bgp.provider_rel(sasn, iasn) for sasn in succs if sasn != iasn):
                    if votes[iasn] > max(votes.values()) / 2:
                        return iasn, IASN_SUCC_HALF

        votes_rels: List[int] = [vasn for vasn in votes if
                                 vasn == iasn or self.bgp.rel(iasn, vasn) or self.as2org[iasn] ==
                                 self.as2org[vasn]]
        if DEBUG: print('Vote Rels: {}'.format(votes_rels))
        if len(votes_rels) < 2:
            asns = max_num(votes, key=votes.__getitem__)
            if DEBUG: print('ASNs: {}'.format(asns))
        else:
            for vasn in list(votes):
                if vasn not in votes_rels:
                    for vr in votes_rels:
                        if self.as2org[vr] == self.as2org[vasn]:
                            votes[vr] += votes.pop(vasn, 0)
            asns = max_num(votes_rels, key=votes.__getitem__)
            othermax = max(votes, key=votes.__getitem__)
            if DEBUG:
                print('ASNs: {}'.format(asns))
                print('Othermax: {}'.format(othermax))
            if router.nexthop and votes[othermax] > votes[asns[0]] * 4:
                utype += 3000
                return othermax, utype

        if len(asns) == 1:
            asn = asns[0]
            utype += VOTE_SINGLE
        else:
            asn = min(asns, key=lambda x: (self.bgp.conesize[x], -x))
            utype += VOTE_TIE
        if iasn > 0 and asn != iasn and not self.bgp.rel(iasn, asn):
            return self.hidden_asn(iasn, asn, utype, votes)
        return asn, utype

    def annotate_routers(self, routers: Collection[Router], increment=100000):
        pb = Progress(len(routers), 'Annotating routers', increment=increment)
        for router in pb.iterator(routers):
            asn, utype = self.annotate_router(router)
            self.rupdates.add_update(router, asn, self.as2org[asn], utype)

    def annotate_interface(self, interface: Interface):
        edges: Dict[Router, int] = interface.pred
        # priority = bdrmapit.graph.iedges.priority[interface]
        if DEBUG:
            # log.debug('Edges: {}'.format(edges))
            print('VRF: {}'.format(interface.vrf))
        votes = Counter()
        for rpred, num in edges.items():
            asn = self.rupdates.asn(rpred)
            if DEBUG:
                print('Router={}, RASN={}'.format(rpred.name, asn))
            votes[asn] += num
        if DEBUG:
            print('Votes: {}'.format(votes))
        if len(votes) == 1:
            return peek(votes), 1 if len(edges) > 1 else 0
        asns = max_num(votes, key=votes.__getitem__)
        if DEBUG:
            print('MaxNum: {}'.format(asns))
        rels = [asn for asn in asns if interface.asn == asn or self.bgp.rel(interface.asn, asn)]
        if not rels:
            rels = asns
        if DEBUG:
            print('Rels: {}'.format(rels))
            print('Sorted Rels: {}'.format(sorted(rels, key=lambda x: (
                x != interface.asn, -self.bgp.provider_rel(interface.asn, x), -self.bgp.conesize[x], x))))
        # asn = max(asns, key=lambda x: (x == interface.asn, bdrmapit.bgp.conesize[x], -x))
        asn = min(rels, key=lambda x: (
        x != interface.asn, -self.bgp.provider_rel(interface.asn, x), -self.bgp.conesize[x], x))
        utype = 1 if len(asns) == 1 and len(edges) > 1 else 2
        return asn, utype

    def annotate_interface2(self, interface: Interface):
        edges: Dict[Router, int] = interface.pred
        # priority = bdrmapit.graph.iedges.priority[interface]
        if DEBUG:
            # log.debug('Edges: {}'.format(edges))
            print('VRF: {}'.format(interface.vrf))
        votes = Counter()
        for rpred, num in edges.items():
            asn = self.rupdates.asn(rpred)
            if DEBUG:
                print('Router={}, RASN={}'.format(rpred.name, asn))
            votes[asn] += num + len(rpred.succ)
        if DEBUG:
            print('Votes: {}'.format(votes))
        if len(votes) == 1:
            return peek(votes), 1 if len(edges) > 1 else 0
        asns = max_num(votes, key=votes.__getitem__)
        if DEBUG:
            print('MaxNum: {}'.format(asns))
        rels = [asn for asn in asns if interface.asn == asn or self.bgp.rel(interface.asn, asn)]
        if not rels:
            rels = asns
        if DEBUG:
            print('Rels: {}'.format(rels))
            print('Sorted Rels: {}'.format(sorted(rels, key=lambda x: (
                x != interface.asn, -self.bgp.provider_rel(interface.asn, x), -self.bgp.conesize[x], x))))
        # asn = max(asns, key=lambda x: (x == interface.asn, bdrmapit.bgp.conesize[x], -x))
        asn = min(rels, key=lambda x: (x != interface.asn, -self.bgp.provider_rel(interface.asn, x), -self.bgp.conesize[x], x))
        utype = 1 if len(asns) == 1 and len(edges) > 1 else 2
        return asn, utype

    def annotate_interfaces(self, interfaces: Collection[Interface]):
        pb = Progress(len(interfaces), 'Adding links', increment=100000)
        for interface in pb.iterator(interfaces):
            if interface.asn >= 0:
                # asn, utype = annotate_interface(bdrmapit, interface, rupdates, iupdates)
                # asn, utype = self.annotate_interface(interface)
                asn, utype = self.annotate_interface2(interface)
                # asn, utype = self.annotate_interface_super(interface)
                self.iupdates.add_update(interface, asn, self.as2org[asn], utype)

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


def construct_graph(addrs, nexthop, multi, dps, mpls, ip2as, as2org, nodes_file=None):
    interfaces = {}
    routers = {}
    with File2(nodes_file, 'rt') as f:
        for line in f:
            if line[0] != '#':
                _, nid, *addrs = line.split()
                nid = nid[:-1]
                router = Router(nid)
                routers[router.name] = router
                for addr in addrs:
                    asn = ip2as.asn(addr)
                    if asn > 0 or asn <= -100:
                        interface = Interface(addr, asn, as2org[asn])
                        interfaces[addr] = interface
                        interface.router = router
                        router.interfaces.append(interface)
    for i in range(len(addrs)):
        addr = addrs[i]
        asn = ip2as.asn(addr)
        interface = Interface(addr, asn, as2org[asn])
        interfaces[addr] = interface
    for addr in mpls:
        interface = interfaces[addr]
        interface.mpls = True
    for interface in interfaces.values():
        if not interface.router:
            router = Router(interface.addr)
            interface.router = router
            router.interfaces.append(interface)
            routers[router.name] = router
    for addr, edges in nexthop.items():
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
    for addr in multi:
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
    for addr, dests in dps.items():
        interface = interfaces[addr]
        interface.dests.update(dests)
    return Graph(interfaces=interfaces, routers=routers)
