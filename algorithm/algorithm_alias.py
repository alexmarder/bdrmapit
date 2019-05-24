import sys
from collections import Counter, defaultdict
from typing import Collection, List, Set, Dict, DefaultDict, Union, Tuple, Counter as TCounter

from traceutils.as2org.as2org import AS2Org
from traceutils.bgp.bgp import BGP
from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress
from traceutils.utils.utils import max_num, peek

# from bdrmapit_parser.algorithm.bdrmapit import Bdrmapit
from bdrmapit_parser.algorithm.updates_dict import Updates, UpdatesView, UpdateObj
from bdrmapit_parser.graph.construct import Graph
from bdrmapit_parser.graph.node import Router, Interface
import heapq as hq

from vrf.prepare import VRFPrep
from vrf.vrfedge import VRFEdge, VType

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

    def __init__(self, bdrmapit=None, rupdates=None, iupdates=None):
        self.old = DEBUG
        self.bdrmapit = bdrmapit
        self.rupdates = rupdates
        self.iupdates = iupdates
        self.old_rupdates = None
        self.old_iupdates = None

    def __enter__(self):
        global DEBUG
        DEBUG = True
        if self.bdrmapit is not None:
            if self.rupdates is not None:
                self.old_rupdates, self.bdrmapit.rupdates = self.bdrmapit.rupdates, self.rupdates
            if self.iupdates is not None:
                self.old_iupdates, self.bdrmapit.iupdates = self.bdrmapit.iupdates, self.iupdates

    def __exit__(self, exc_type, exc_val, exc_tb):
        global DEBUG
        DEBUG = self.old
        if self.bdrmapit is not None:
            if self.rupdates is not None:
                self.bdrmapit.rupdates = self.old_rupdates
            if self.iupdates is not None:
                self.bdrmapit.iupdates = self.old_iupdates
        return False


class Bdrmapit:

    def __init__(self, graph: Graph, as2org: AS2Org, bgp: BGP, strict=True):
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
        self.strict = strict

    def test_router(self, nid, rupdates=None, iupdates=None):
        with Debug(self, rupdates=rupdates, iupdates=iupdates):
            r: Router = self.graph.routers[nid]
            if r.vrf:
                result = self.annotate_router_vrf(r)
            else:
                result = self.annotate_router(r)
        print(result)

    def test_interface(self, addr, rupdates=None, iupdates=None):
        with Debug(self, rupdates=rupdates, iupdates=iupdates):
            i = self.graph.interfaces[addr]
            result = self.annotate_interface(i)
        print(result)

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
        skipped = 0
        pb = Progress(len(self.routers_mpls), 'Annotating MPLS routers', increment=100000, callback=lambda: 'Skipped {:,d}'.format(skipped))
        for router in pb.iterator(self.routers_mpls):
            origins = Counter()
            for interface in router.interfaces:
                if interface.mpls:
                    origins[interface.asn] += 1
            if len(origins) > 1:
                skipped += 1
                if router.succ:
                    self.routers_succ.append(router)
                else:
                    self.lasthops.append(router)
            if len(origins) == 1:
                asn = peek(origins)
                org = self.as2org[asn]
                self.rupdates.add_update_direct(router, asn, org, 2)

    def heaptest(self, rdests: Set[int], interfaces: List[Interface]):
        heap = []
        for a in rdests:
            hq.heappush(heap, (self.bgp.conesize[a], -a, a))
        original_min = heap[0][-1]
        while heap:
            dest = hq.heappop(heap)[-1]
            if any(interface.asn == dest or self.bgp.rel(interface.asn, dest) for interface in interfaces):
                return dest
        return original_min

    def annotate_lasthop(self, router: Router):
        if DEBUG: print('Dests: {}'.format(router.dests))
        interfaces = router.interfaces
        iasns = Counter(interface.asn for interface in interfaces)

        # If no destination ASes
        if len(router.dests) == 0 or all(dest <= 0 for dest in router.dests):
            if len(iasns) == 0:
                return -1, NODEST
            return max(iasns, key=lambda x: (iasns[x], -self.bgp.conesize[x], x)), NODEST

        # Check for single organization
        rorgs = {self.as2org[d] for d in router.dests}
        if len(rorgs) == 1:
            if DEBUG: print('Single Org: {}'.format(router.dests))
            dest = peek(router.dests)
            utype = SINGLE

        # Multiple destination organization
        else:
            if DEBUG: print('IASNs: {}'.format(iasns))
            dest = self.heaptest(router.dests, interfaces)
            utype = HEAPED

        # If the interface AS has no relationship to the selected AS, check for hidden AS
        if all(iasn > 0 and iasn != dest and not self.bgp.rel(iasn, dest) for iasn in iasns):
            if DEBUG: print('No Rel: {}-{}'.format(iasns, dest))
            intersection = self.bgp.providers[dest] & self.multi_customers(iasns)
            # Only use intersection AS if it is definitive
            if len(intersection) == 1:
                dest = peek(intersection)
                return dest, MISSING_INTER
            # Otherwise, use the interface AS
            else:
                if DEBUG: print(self.bgp.providers[dest] & self.multi_peers(iasns))
                if self.strict:
                    return max(iasns, key=lambda x: (iasns[x], -self.bgp.conesize[x], x)), MISSING_NOINTER
                else:
                    return dest, MISSING_NOINTER
        return dest, utype

    def multi_customers(self, asns):
        return {customer for asn in asns for customer in self.bgp.customers[asn]}

    def multi_peers(self, asns):
        return {peer for asn in asns for peer in self.bgp.peers[asn]}

    def multi_providers(self, asns):
        return {provider for asn in asns for provider in self.bgp.providers[asn]}

    def any_rels(self, asn, others):
        for other in others:
            if self.bgp.rel(asn, other):
                return True
        return False

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
            try:
                self.rupdates.add_update_direct(router, dest, self.as2org[dest], utype)
            except:
                print(dest, utype)
                raise

    def router_heuristics(self, router: Router, isucc: Interface, origins: Set[int], iasns: TCounter[int]):
        rsucc: Router = isucc.router
        rsucc_asn = self.rupdates.asn(rsucc)
        iupdate = self.iupdates[isucc]
        if iupdate and rsucc_asn == isucc.asn:
            succ_asn = iupdate.asn
            succ_org = iupdate.org
        else:
            succ_asn = isucc.asn
            succ_org = isucc.org
        if DEBUG:
            print('\tASN={}, RASN={}, IUpdate={} VRF={}'.format(isucc.asn, rsucc_asn, succ_asn, router.vrf))

        # If subsequent interface AS has no known origin, use subsequent router AS
        if isucc.asn == 0 or router.vrf:
            return rsucc_asn

        # If subsequent interface is an IXP interface, use interface AS
        if isucc.asn <= -100:
            if any(iasn > 0 for iasn in origins):
                return max(origins, key=lambda x: (iasns[x], self.bgp.conesize[x], -x))
            return -1

        # If subsequent interface AS is the same as the interface AS, use it
        if isucc.asn in origins:
            return isucc.asn

        # If subsequent router AS is different from the subsequent interface AS
        if rsucc_asn > 0 and rsucc_asn != succ_asn and not any(succ_org == self.as2org[iasn] for iasn in origins):
            # print(succ_org, {self.as2org[iasn] for iasn in origins})
            if DEBUG: print('\tThird party: Router={}, RASN={}'.format(rsucc.name, rsucc_asn))
            if rsucc_asn in origins or self.any_rels(rsucc_asn, origins):
                if DEBUG: print('\tISUCC in Dests: {} in {}'.format(succ_asn, router.dests))
                if succ_asn not in router.dests:
                    return rsucc_asn
                elif self.bgp.rel(succ_asn, rsucc_asn) and not self.any_rels(succ_asn, origins):
                    return rsucc_asn
        # When there is no relationship between router ASes and subsequent interface AS,
        # check if relationship between router ASes and subsequent router AS when they are the same org
        if succ_org == self.as2org[rsucc_asn]:
            if not any(self.bgp.rel(iasn, succ_asn) for iasn in iasns):
                if any(self.bgp.rel(iasn, rsucc_asn) for iasn in iasns):
                    if DEBUG: print('Testing')
                    return rsucc_asn
        if succ_asn <= 0 or (0 < rsucc_asn != isucc.asn):
            if DEBUG:
                print('ugh')
            return isucc.asn
        return succ_asn

    def vrf_heuristics(self, edge: VRFEdge, origins: Set[int], iasns: TCounter[int]):
        rsucc: Router = edge.node
        vtype = edge.vtype
        if DEBUG: print('VType={}'.format(vtype))
        if vtype.value == VType.forwarding.value or vtype.value == VType.both.value:
            rsucc_asn = self.rupdates.asn(rsucc)
            if DEBUG: print('ASN={}'.format(rsucc_asn))
        elif vtype.value == VType.toforward.value:
            rsucc_asn = max(origins, key=lambda x: (iasns[x], self.bgp.conesize[x], -x))
            if DEBUG: print('ASN={}'.format(rsucc_asn))
        else:
            raise Exception('What the fuck')
        return rsucc_asn

    def hidden_asn(self, iasns: TCounter[int], asn: int, utype: int, votes: Dict[int, int]):
        """
        Look for hidden AS between the interface AS and the selected AS.
        """
        intasn: int = None
        # First look for customers of interface AS who are providers of selected AS
        intersection: Set[int] = self.multi_customers(iasns) & self.bgp.providers[asn]
        # Only use if the intersection is definitive, i.e., a single AS
        if len(intersection) == 1:
            intasn = peek(intersection)
            if DEBUG: print('Hidden: {}'.format(intasn))

        # If there is no intersection, check for provider of interface AS who is customer of selected AS
        elif not intersection:
            intersection = self.multi_providers(iasns) & self.bgp.customers[asn]
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

        if DEBUG: print('Missing: {}-{}'.format(iasns, asn))
        # If a sibling of the selected AS has a relationship to the interface AS, use the sibling
        for sibasn in self.as2org.siblings[asn]:
            if self.any_rels(sibasn, iasns):
                return sibasn, 200000 + utype

        # If a sibling of the interface AS has a relationship to the selected AS, use the selected AS
        for iasn in iasns:
            for sibasn in self.as2org.siblings[iasn]:
                if self.bgp.rel(sibasn, asn):
                    return asn, 300000 + utype
                    # return sibasn, 300000 + utype
        if self.strict:
            return max(iasns, key=lambda x: (votes[x], -self.bgp.conesize[x], x)), HIDDEN_NOINTER + utype
        else:
            return asn, HIDDEN_NOINTER + utype

    def annotate_router_vrf(self, router: Router):
        edge: VRFEdge
        utype: int = 0

        iasns: TCounter[int] = Counter(interface.asn for interface in router.interfaces if interface.asn > 0)
        if DEBUG:
            print('IASN: {}'.format(iasns))
            print('Edges={}, NH={}'.format(len(router.succ), router.nexthop))
            print('VRF={}'.format(router.vrf))
            print('MPLS?: {}'.format(any(i.mpls for i in router.interfaces)))

        # Use heuristics to determine link votes
        vtype = None
        succs = Counter()
        sasn_origins = defaultdict(set)
        for edge in router.succ:
            origins = router.origins[edge]
            if DEBUG: print('Succ={}, ASN={}'.format(edge.node.name, self.rupdates[edge.node]))
            succ_asn = self.vrf_heuristics(edge, origins, iasns)
            if vtype is None:
                vtype = edge.vtype
            elif vtype.value != edge.vtype.value:
                vtype = VType.both
            if DEBUG: print('Heuristic: {}'.format(succ_asn))
            if succ_asn > 0:
                succs[succ_asn] += 1
                sasn_origins[succ_asn].update(origins)
        if DEBUG:
            print('Succs: {}'.format(succs))
            print('VType: {}'.format(vtype))

        # Create votes counter and add interface AS
        votes = succs + iasns
        if DEBUG: print('Votes: {}'.format(votes))
        if not votes:
            return -1, -1

        votes_rels: List[int] = [vasn for vasn in votes if any(
            vasn == iasn or self.bgp.rel(iasn, vasn) or self.as2org[iasn] == self.as2org[vasn] for iasn in iasns)]
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
            if DEBUG: print('Conesizes: {}'.format({a: self.bgp.conesize[a] for a in asns}))
            if vtype.value == VType.forwarding.value:
                asn = max(asns, key=lambda x: (self.bgp.conesize[x], -x))
            else:
                asn = min(asns, key=lambda x: (self.bgp.conesize[x], -x))
            utype += VOTE_TIE
        return asn, utype

    def annotate_router(self, router: Router):
        isucc: Union[Interface, VRFEdge]
        utype: int = 0

        iasns: TCounter[int] = Counter(interface.asn for interface in router.interfaces if interface.asn > 0)
        if DEBUG:
            print('IASN: {}'.format(iasns))
            print('Edges={}, NH={}'.format(len(router.succ), router.nexthop))
            print('VRF={}'.format(router.vrf))
            print('MPLS?: {}'.format(any(i.mpls for i in router.interfaces)))

        # utype += reallocated(bdrmapit, router, edges, rupdates, succs, succ_origins)

        # Use heuristics to determine link votes
        succs = Counter()
        sasn_origins = defaultdict(set)
        for isucc in router.succ:
            origins = router.origins[isucc]
            if router.vrf:
                if DEBUG: print('Succ={}, ASN={}'.format(isucc.node.name, self.rupdates[isucc.node]))
                succ_asn = self.vrf_heuristics(isucc, origins, iasns)
            else:
                if DEBUG: print('Succ={}, ASN={}, Origins={}'.format(isucc.addr, isucc.asn, origins))
                succ_asn = self.router_heuristics(router, isucc, origins, iasns)
            # succ_asn = self.router_heuristics(router, isucc, origins, iasns)
            if DEBUG: print('Heuristic: {}'.format(succ_asn))
            if succ_asn > 0:
                succs[succ_asn] += 1
                sasn_origins[succ_asn].update(origins)
        if DEBUG: print('Succs: {}'.format(succs))

        # Deal specially with cases where there is only a single subsequent AS
        if len(succs) == 1 or len({self.as2org[sasn] for sasn in succs}) == 1:
            sasn = peek(succs) if len(succs) == 1 else max(succs, key=lambda x: (self.bgp.conesize[x], -x))
            if not iasns:
                return sasn, utype + SINGLE_SUCC_ORIGIN

            # Subsequent AS = Interface AS
            if sasn in iasns:
                return sasn, utype + SINGLE_SUCC_ORIGIN

            # Subsequent AS is customer of interface AS
            if sasn in self.multi_customers(sasn_origins[sasn]):
                if DEBUG: print('Provider: {}->{}'.format(sasn_origins[sasn], sasn))
                return sasn, utype + SINGLE_SUCC_4

            # No relationship between interface AS and subsequent AS
            if not self.any_rels(sasn, sasn_origins[sasn]):
                # if not self.bgp.rel(iasn, sasn) and self.bgp.conesize[iasn] > self.bgp.conesize[sasn]:
                rels = [iasn for iasn in iasns if self.bgp.rel(iasn, sasn)]
                if rels:
                    return max(rels, key=lambda x: (iasns[x], self.bgp.conesize[x], -x)), 400000
                return self.hidden_asn(iasns, sasn, utype, iasns)

            # Not sure what I'm trying to do here
            if not router.vrf:
                for isucc in router.succ:
                    supdate = self.iupdates[isucc]
                    if supdate:
                        sasn2 = supdate.asn
                        itype = supdate.utype
                        rasn = self.rupdates.asn(isucc.router)
                        if sasn2 == sasn and ((rasn == sasn and itype == 1) or rasn != sasn):
                            return sasn, utype + IUPDATE

            # Or here
            if not router.vrf:
                rasns = set()
                for isucc in router.succ:
                    rasn = self.rupdates.asn(isucc.router)
                    rasns.add(rasn if rasn > 0 else sasn)
                if DEBUG: print('RASNS={}, SASN={}'.format(rasns, sasn))
                if sasn not in rasns:
                    return sasn, utype + SINGLE_SUCC_RASN

                # Check if interface AS is customer of subsequent AS
                for iasn in iasns:
                    if self.bgp.customer_rel(sasn, iasn):
                        # Surely, I meant iasn and not sasn
                        return iasn, utype + REMAINING_4
                        # return sasn, utype + REMAINING_4

        # Create votes counter and add interface AS
        votes = succs + iasns
        if DEBUG: print('Votes: {}'.format(votes))
        if not votes:
            return -1, -1

        # More than 1 subsequent AS
        if len(succs) > 1:
            if len(iasns) == 1:
                iasn = peek(iasns)
                noiasn = Counter(succs)
                noiasn[iasn] = 0
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

        votes_rels: List[int] = [vasn for vasn in votes if any(vasn == iasn or self.bgp.rel(iasn, vasn) or self.as2org[iasn] == self.as2org[vasn] for iasn in iasns)]
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
            if DEBUG: print('Conesizes: {}'.format({a: self.bgp.conesize[a] for a in asns}))
            asn = min(asns, key=lambda x: (self.bgp.conesize[x], -x))
            utype += VOTE_TIE
        if iasns and all(asn != iasn and not self.bgp.rel(iasn, asn) for iasn in iasns):
            return self.hidden_asn(iasns, asn, utype, votes)
        return asn, utype

    def annotate_routers(self, routers: Collection[Router], increment=100000):
        pb = Progress(len(routers), 'Annotating routers', increment=increment)
        for router in pb.iterator(routers):
            if router.vrf:
                asn, utype = self.annotate_router_vrf(router)
            else:
                asn, utype = self.annotate_router(router)
            # asn, utype = self.annotate_router(router)
            self.rupdates.add_update(router, asn, self.as2org[asn], utype)

    def annotate_interface(self, interface: Interface):
        edges: Dict[Router, int] = interface.pred
        # priority = bdrmapit.graph.iedges.priority[interface]
        if DEBUG:
            # log.debug('Edges: {}'.format(edges))
            print('ASN: {}'.format(interface.asn))
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
        asn = min(rels, key=lambda x: (x != interface.asn, -self.bgp.provider_rel(interface.asn, x), -self.bgp.conesize[x], x))
        utype = 1 if len(asns) == 1 and len(edges) > 1 else 2
        return asn, utype

    def annotate_interface2(self, interface: Interface):
        edges: Dict[Router, int] = interface.pred
        total_succ = sum(len(router.succ) * num for router, num in edges.items())
        # priority = bdrmapit.graph.iedges.priority[interface]
        if DEBUG:
            # log.debug('Edges: {}'.format(edges))
            print('ASN: {}'.format(interface.asn))
            print('VRF: {}'.format(interface.vrf))
        votes = Counter()
        votes_tie = defaultdict(lambda: 0)
        for rpred, num in edges.items():
            asn = self.rupdates.asn(rpred)
            if DEBUG:
                print('Router={}, RASN={}'.format(rpred.name, asn))
            votes[asn] += num
            votes_tie[asn] += num * (len(rpred.succ) / total_succ)
        if DEBUG:
            print('Votes: {}'.format(dict(votes)))
            print('Votes Tie: {}'.format(dict(votes_tie)))
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
        asn = min(rels, key=lambda x: (-votes_tie[x], x != interface.asn, -self.bgp.provider_rel(interface.asn, x), -self.bgp.conesize[x], x))
        utype = 1 if len(asns) == 1 and len(edges) > 1 else 2
        return asn, utype

    def annotate_interfaces(self, interfaces: Collection[Interface]):
        pb = Progress(len(interfaces), 'Adding links', increment=100000)
        for interface in pb.iterator(interfaces):
            if interface.asn >= 0:
                # asn, utype = annotate_interface(bdrmapit, interface, rupdates, iupdates)
                asn, utype = self.annotate_interface(interface)
                # asn, utype = self.annotate_interface2(interface)
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


def construct_graph(addrs, nexthop, multi, dps, mpls, ip2as, as2org, nodes_file=None, increment=100000):
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


# def add_forwarding(graph: Graph, vrfprep: VRFPrep):
#     for addr, edges in vrfprep.bedges:
#         if addr in vrfprep.fnext:
#             interface = graph.interfaces[addr]
#             router = interface.router
#             router.nexthop = True
#             router.vrf = True
#             for i in range(len(edges)):
#                 edge = edges[i]
#                 succ = graph.interfaces[edge]
#                 if succ in router.succ:
#                     origins = router.origins[succ]
#                     origins.add(interface.asn)
#                 else:
#                     router.succ.add(succ)
#                     router.origins[succ] = {interface.asn}
#         elif addr 
                # predcount = succ.pred.get(router, 0)
                # succ.pred[router] = predcount + 1
