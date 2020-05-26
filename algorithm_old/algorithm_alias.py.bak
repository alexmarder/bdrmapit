import sys
from collections import Counter, defaultdict
from typing import Collection, List, Set, Dict, Union, Counter as TCounter, Optional

from traceutils.as2org.as2org import AS2Org
from traceutils.bgp.bgp import BGP
from traceutils.progress.bar import Progress
from traceutils.utils.utils import max_num, peek

from bdrmapit_parser.algorithm.updates_dict import Updates
from bdrmapit_parser.graph.construct import Graph
from bdrmapit_parser.graph.node import Router, Interface
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

    def __init__(self, bdrmapit=None, rupdates=None, iupdates=None, verbose=True):
        self.old = DEBUG
        self.bdrmapit = bdrmapit
        self.rupdates = rupdates
        self.iupdates = iupdates
        self.old_rupdates = None
        self.old_iupdates = None
        self.verbose = verbose

    def __enter__(self):
        global DEBUG
        DEBUG = self.verbose
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

    def __init__(self, graph: Graph, as2org: AS2Org, bgp: BGP, strict=True, skipua=False, hidden_reverse=True):
        self.graph = graph
        self.as2org = as2org
        self.bgp = bgp
        self.rupdates = Updates()
        self.iupdates = Updates()
        self.routers_mpls: List[Router] = []
        self.lasthops: List[Router] = []
        self.routers_succ: List[Router] = []
        self.routers_vrf: List[Router] = []
        for router in graph.routers.values():
            if router.succ:
                if router.vrf:
                    self.routers_vrf.append(router)
                else:
                    self.routers_succ.append(router)
            else:
                self.lasthops.append(router)
        self.routers_vrf = sorted(self.routers_vrf, key=self.sort_vrf)
        self.interfaces_pred: List[Interface] = [i for i in graph.interfaces.values() if i.pred]
        self.previous_updates = []
        self.strict = strict
        self.skipua = skipua
        self.hidden_reverse = hidden_reverse

    def test_last(self, nid, rupdates=None, iupdates=None):
        if rupdates is None:
            rupdates = Updates()
        if iupdates is None:
            iupdates = Updates()
        with Debug(self, rupdates=rupdates, iupdates=iupdates):
            if not isinstance(nid, Router):
                r: Router = self.graph.routers[nid]
            else:
                r = nid
            result = self.annotate_lasthop(r)
        print(result)

    def test_router(self, nid, rupdates=None, iupdates=None):
        with Debug(self, rupdates=rupdates, iupdates=iupdates):
            try:
                r: Router = self.graph.routers[nid]
            except KeyError:
                r: Router = self.graph.interfaces[nid].router
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

    def set_dests(self, increment=1000000):
        """
        Set destination AS sets for each router, and remove potential relocated prefixes for last hop interfaces.
        :param increment: status increment
        """
        modified = 0
        pb = Progress(len(self.graph.routers), 'Setting destinations', increment=increment, callback=lambda: 'Modified {:,d}'.format(modified))
        for router in pb.iterator(self.graph.routers.values()):
            for interface in router.interfaces:
                # Copy destination ASes to avoid messing up original
                idests: Set[int] = set(interface.dests)
                # If last hop, interface has non-IXP AS mapping, and interface has destination ASes
                if not router.succ and idests and interface.asn > 0:
                    origin = interface.asn
                    # Interface must have exactly 2 destination ASes and one must be its origin AS
                    if len(idests) == 2 and origin in idests:
                        other_asn = peek(idests - {origin})  # other AS
                        # If other AS is likely customer of interface origin AS, and it's a small AS
                        if self.bgp.conesize[origin] > self.bgp.conesize[other_asn] and self.bgp.conesize[other_asn] < 5:
                            idests.discard(origin)
                            modified += 1
                # Add all remaining destination ASes to the router destination AS set
                router.dests.update(idests)

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

    def annotate_lasthop_nodests(self, iasns):
        if DEBUG: print('No dests')
        # No interface origin ASes. Only cause is the addresses had no matching prefix.
        if len(iasns) == 0:
            # No AS mapping possible with current method.
            # TODO: Might be worth looking backward for mapping. Need to investigate how common.
            return -1, 1
        # Single router origin AS, so select it.
        elif len(iasns) == 1:
            return peek(iasns), 2
        # Collect ASes that have a relationship to all other ASes.
        allrels = {iasn for iasn in iasns if all(self.as2org[iasn] == self.as2org[oasn] or self.bgp.rel(iasn, oasn) for oasn in iasns if iasn != oasn)}
        if allrels:
            if DEBUG:
                for asn in allrels:
                    print('{}: {}'.format(asn, iasns[asn]))
            # Select AS (with relationship to all others) with the most votes, then smallest customer cone.
            return max(allrels, key=lambda x: (iasns[x], -self.bgp.conesize[x], x)), 3
        # No AS is directly connected (according to BGP) with every other origin AS.
        # Try to select a single AS that is a customer of all origin ASes.
        hidden = []  # List of customer sets
        for iasn in iasns:
            # rels = self.bgp.providers[iasn] | self.bgp.peers[iasn] | self.bgp.customers[iasn]
            rels = self.bgp.customers[iasn]
            hidden.append(rels)
        # Take intersection of all customer sets
        intersection: Set[int] = hidden[0]
        for rels in hidden[1:]:
            intersection.intersection_update(rels)
        # If single AS intersection, select it
        if len(intersection) == 1:
            return peek(intersection), 4
        if DEBUG:
            for iasn in iasns:
                print('{}: {}'.format(iasn, iasns[iasn]))
        # Select the most frequent origin AS, break ties with smallest customer cone size
        return max(iasns, key=lambda x: (iasns[x], -self.bgp.conesize[x], x)), 5

    def annotate_lasthop_norels(self, dests, iasns):
        if self.strict:
            return max(iasns, key=lambda x: (iasns[x], -self.bgp.conesize[x], x)), NODEST
        if iasns:
            if DEBUG: print('IASNs: {}'.format(iasns))
            if DEBUG:
                print('Providers: {}'.format(self.multi_providers(dests)))
            intersection = self.multi_providers(dests) & self.multi_customers(iasns)
            if len(intersection) == 1:
                if DEBUG: print('Inter Cust: {}'.format(intersection))
                return peek(intersection), 10000
            # intersection = self.multi_providers(dests) & self.multi_peers(iasns)
            # if len(intersection) == 1:
            #     return peek(intersection), 30000
            intersection = self.multi_customers(dests) & self.multi_providers(iasns)
            if len(intersection) == 1:
                return peek(intersection), 20000
        asn = min(dests, key=lambda x: (self.bgp.conesize[x], -x))
        return asn, MISSING_NOINTER

    def annotate_lasthop(self, router: Router):
        dests = router.dests
        if DEBUG: print('Dests: {}'.format(dests))
        iasns = Counter(interface.asn for interface in router.interfaces if interface.asn > 0)
        # No destination ASes
        if len(router.dests) == 0 or all(dest <= 0 for dest in router.dests):
            return self.annotate_lasthop_nodests(iasns)
        # Use overlapping ASes if available
        overlap = iasns.keys() & dests
        if DEBUG: print('Dest IASN intersection: {}'.format(overlap))
        if overlap:
            if len(overlap) == 1:
                return peek(overlap), HEAPED
            return min(overlap, key=lambda x: (self.bgp.conesize[x], -x)), HEAPED
        # No overlapping ASes, use relationship ASes
        rels = {dasn for dasn in dests if self.any_rels(dasn, iasns)}
        if DEBUG: print('Rels: {}'.format(rels))
        if rels:
            # Select overlapping or relationship AS with largest customer cone
            return min(rels, key=lambda x: (self.bgp.conesize[x], -x)), HEAPED
            # return max(rels, key=lambda x: (len(self.bgp.cone[x] & dests), -x)), HEAPED
        # No relationship between any origin AS and any destination AS
        return self.annotate_lasthop_norels(dests, iasns)

    def annotate_lasthops(self, routers=None):
        if routers is None:
            routers = self.lasthops
        pb = Progress(len(routers), message='Last Hops', increment=100000)
        for router in pb.iterator(routers):
            dest, utype = self.annotate_lasthop(router)
            self.rupdates.add_update_direct(router, dest, self.as2org[dest], utype)

    def router_heuristics(self, router: Router, isucc: Interface, origins: Set[int], iasns: TCounter[int]):
        rsucc: Router = isucc.router  # subsequent router
        rsucc_asn = self.rupdates.asn(rsucc)  # subsequent router AS annotation
        iupdate = self.iupdates[isucc]  # update for subsequent interface (interface annotation)

        # If subsequent interface is an IXP interface, use interface AS
        if isucc.asn <= -100:
            return -1

        # If subsequent interface AS has no known origin, use subsequent router AS
        if isucc.asn == 0:
            return rsucc_asn if not self.skipua else -1

        if iupdate and rsucc_asn == isucc.asn:
            succ_asn = iupdate.asn
            succ_org = iupdate.org
            if succ_asn <= 0:
                succ_asn = isucc.asn
                succ_org = isucc.org
        else:
            succ_asn = isucc.asn
            succ_org = isucc.org
        if DEBUG:
            print('\tASN={}, RASN={}, IUpdate={} VRF={}'.format(isucc.asn, rsucc_asn, succ_asn, router.vrf))

        # Third party stuff
        third = False
        if not any(isucc.org == self.as2org[iasn] for iasn in origins):
            # If here, subsequent interface is not in IR origin ASes
            if rsucc_asn > 0:
                # If here, the subsequent router has an AS annotation
                rsucc_org = self.as2org[rsucc_asn]
                if rsucc_org != succ_org and not any(succ_org == self.as2org[iasn] for iasn in origins):
                    # If here, subsequent router AS is different from the subsequent interface AS
                    if DEBUG:
                        print('\tThird party: Router={}, RASN={}'.format(rsucc.name, rsucc_asn))
                        print('\tAny origin-router rels? {}'.format(rsucc_asn in origins or self.any_rels(rsucc_asn, origins)))
                    if rsucc_asn in origins or self.any_rels(rsucc_asn, origins):
                        # If here, some origin AS matches the subsequent router's AS annotation
                        # Or, some origin AS directly interconnects with the subsequent routers AS annotation

                        # Number of destination in subsequent interface origin AS customer cone
                        s_conesize = len(router.dests & self.bgp.cone[succ_asn])
                        # Number of destination in subsequent router AS annotation customer cone
                        r_conesize = len(router.dests & self.bgp.cone[rsucc_asn])
                        if DEBUG:
                            if len(router.dests) <= 5:
                                print('\tISUCC in Dests: {} in {}'.format(succ_asn, router.dests))
                            else:
                                print('\tISUCC not in Dests: {}'.format(succ_asn not in router.dests))
                            print('\t{} < {}'.format(s_conesize, r_conesize))
                        if succ_asn not in router.dests:
                            # If here, the subsequent AS is not in the router's destination ASes
                            if s_conesize <= r_conesize:
                                # If here, at least as many destinations are in the router AS annotation cone than in the subsequent interface origin AS cone
                                third = True
                        elif not self.any_rels(succ_asn, origins) and self.bgp.rel(succ_asn, rsucc_asn):
                            # If here, none of the origins connect to the subsequent interface origin AS,
                            # and the subsequent interface AS has a relationship with the router AS annotation.
                            third = True

            # When there is no relationship between router ASes and subsequent interface AS,
            # check if relationship between router ASes and subsequent router AS when they are the same org
            if succ_org == self.as2org[rsucc_asn]:
                if not any(self.bgp.rel(iasn, succ_asn) for iasn in iasns):
                    if any(self.bgp.rel(iasn, rsucc_asn) for iasn in iasns):
                        if DEBUG: print('Testing')
                        # return rsucc_asn
                        third = True
        if third:
            # Third party was detected!
            rsucc_cone = self.bgp.cone[rsucc_asn]  # subsequent router AS annotation customer cone
            if DEBUG:
                if len(router.dests) <= 5:
                    print('\tDests: {}'.format(router.dests))
                if len(rsucc_cone) <= 5:
                    print('\tCone: {}'.format(rsucc_cone))
            if all(dasn == rsucc_asn or dasn in rsucc_cone for dasn in router.dests):
                # If here, all destination ASes are in the customer cone of the subsequent router's AS annotation
                return rsucc_asn
            if DEBUG:
                for origin in origins:
                    print('\tOrigin {}: RSUCC overlap {} ? SUCC overlap {}'.format(origin, len(router.dests & rsucc_cone), len(router.dests & self.bgp.cone[origin])))
                # print('\tASes not in customer cone for {}'.format(rsucc_asn))
                # for dasn in router.dests:
                #     if dasn not in rsucc_cone and dasn != rsucc_asn:
                #         print('\t\t{}, in succ ASN cone {}'.format(dasn, dasn in self.bgp.cone[succ_asn]))
            # Otherwise, ignore vote
            return -1

        # TODO: Figure out something better to do here
        if succ_asn <= 0 or (rsucc_asn > 0 and rsucc_asn != isucc.asn):
            if DEBUG:
                if succ_asn != isucc.asn:
                    print('ugh')
            succ_asn = isucc.asn
        # if not any(origin == succ_asn or self.bgp.rel(origin, succ_asn) for origin in origins):
        #     if DEBUG: print('\tLooking for hidden. Current={}'.format(succ_asn))
        #     intersection: Set[int] = self.multi_customers(origins) & self.bgp.providers[succ_asn]
        #     if len(intersection) == 1:
        #         succ_asn = peek(intersection)
        #         if DEBUG: print('\tHidden: {}'.format(succ_asn))
        #     if not intersection:
        #         intersection = self.multi_providers(origins) & self.bgp.customers[succ_asn]
        #         if len(intersection) == 1:
        #             succ_asn = peek(intersection)
        #             if DEBUG: print('\tHidden Reversed: {}'.format(succ_asn))
        #     if not intersection:
        #         intersection: Set[int] = self.multi_peers(origins) & self.bgp.providers[succ_asn]
        #         if len(intersection) == 1:
        #             succ_asn = peek(intersection)
        #             if DEBUG: print('\tHidden Peer: {}'.format(succ_asn))
        return succ_asn

    # def vrf_heuristics(self, edge: VRFEdge, origins: Set[int], iasns: TCounter[int]):
    def vrf_heuristics(self, edge: VRFEdge, origins: Set[int]):
        rsucc: Router = edge.node
        vtype = edge.vtype
        if DEBUG: print('VType={}'.format(vtype.name))
        for iface in rsucc.interfaces:
            if iface.asn in origins:
                return iface.asn
        rsucc_asn = self.rupdates.asn(rsucc)
        return rsucc_asn

    def hidden_asn(self, iasns: TCounter[int], asn: int, utype: int, votes: Dict[int, int]):
        """
        Look for hidden AS between the interface AS and the selected AS.
        """
        intasn: Optional[int] = None
        # First look for customers of interface AS who are providers of selected AS
        intersection: Set[int] = self.multi_customers(iasns) & self.bgp.providers[asn]
        # Only use if the intersection is definitive, i.e., a single AS
        if len(intersection) == 1:
            intasn = peek(intersection)
            if DEBUG: print('Hidden: {}'.format(intasn))

        # If there is no intersection, check for provider of interface AS who is customer of selected AS
        elif not intersection and self.hidden_reverse:
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

        # Use heuristics to determine link votes
        vtype = None
        succs = Counter()
        nonvrf = Counter()
        sasn_origins = defaultdict(set)
        for edge in router.succ:
            origins = router.origins[edge]
            if DEBUG: print('Succ={}, ASN={}, VRF={}'.format(edge.node.name, self.rupdates[edge.node], edge.node.vrf))
            # succ_asn = self.vrf_heuristics(edge, origins, iasns)
            succ_asn = self.vrf_heuristics(edge, origins)
            if vtype is None:
                vtype = edge.vtype
            elif vtype.value != edge.vtype.value:
                vtype = VType.both
            if DEBUG: print('Heuristic: {}'.format(succ_asn))
            if succ_asn > 0:
                succs[succ_asn] += 1
                sasn_origins[succ_asn].update(origins)
                if not edge.node.vrf:
                    nonvrf[succ_asn] += 1
        if DEBUG:
            print('Succs: {}'.format(succs))
            print('VType: {}'.format(vtype))

        # Create votes counter and add interface AS
        if DEBUG: print('NonVRF: {}'.format(nonvrf))
        if nonvrf:
            votes = nonvrf
            utype += 50000
        else:
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
            asn = min(asns, key=lambda x: (self.bgp.conesize[x], -x))
            utype += VOTE_TIE
        return asn, utype

    def annotate_router(self, router: Router):
        isucc: Union[Interface, VRFEdge]
        utype: int = 0

        # Router origin ASes
        iasns: TCounter[int] = Counter(interface.asn for interface in router.interfaces if interface.asn > 0)
        if DEBUG:
            if len(router.interfaces) <= 5:
                print('Interfaces: {}'.format(' '.join(i.addr for i in router.interfaces)))
            print('IASN: {}'.format(iasns))
            print('Edges={}, NH={}'.format(len(router.succ), router.nexthop))
            print('VRF={}'.format(router.vrf))

        # Use heuristics to determine link votes
        succs = Counter()  # Subsequent interface vote recorder
        sasn_origins = defaultdict(set)  # Origins seen prior to subsequent interfaces
        # For each subsequent interface
        for isucc in router.succ:
            origins = router.origins[isucc]  # Origins seen prior to subsequent interface
            if DEBUG: print('Succ={}, ASN={}, Origins={} RSucc={}'.format(isucc.addr, isucc.asn, origins, isucc.router.name))
            succ_asn = self.router_heuristics(router, isucc, origins, iasns)  # AS vote for the subsequent interface
            if DEBUG: print('Heuristic: {}'.format(succ_asn))
            # If vote is useful
            if succ_asn > 0:
                succs[succ_asn] += 1  # record vote
                sasn_origins[succ_asn].update(origins)  # record origin ASes seen before interface
        if DEBUG: print('Succs: {}'.format(succs))

        # Deal specially with cases where there is only a single subsequent AS, or subsequent ORG
        # Multihomed exception
        if iasns and len(succs) == 1 or len({self.as2org[sasn] for sasn in succs}) == 1:
            # Subsequent AS
            sasn = peek(succs) if len(succs) == 1 else max(succs, key=lambda x: (self.bgp.conesize[x], -x))
            # Subsequent AS is not in link origin ASes and is a customer of a link origin AS
            if sasn not in sasn_origins[sasn] and sasn in self.multi_customers(sasn_origins[sasn]):
                if DEBUG: print('Provider: {}->{}'.format(sasn_origins[sasn], sasn))
                return sasn, utype + SINGLE_SUCC_4

        # Create votes counter and add interface AS
        votes = succs + iasns
        if DEBUG: print('Votes: {}'.format(votes))
        # if DEBUG:
        #     orgvotes = Counter()
        #     for k, v in votes.items():
        #         orgvotes[self.as2org[k]] += v
        #     print('Vote Orgs: {}'.format(orgvotes))
        if not votes:
            return -1, -1

        # Multiple Peers Exception
        # More than 1 subsequent AS
        if len(succs) > 1:
            # Exactly one router origin AS
            if len(iasns) == 1:
                iasn = peek(iasns)
                # Origin AS is not also a subsequent AS
                if iasn not in succs:
                    # All subsequent ASes are peers of the single origin AS
                    if all(self.bgp.peer_rel(iasn, sasn) for sasn in succs):
                        # Make sure its votes are not dwarfed by subsequent AS
                        if votes[iasn] > max(votes.values()) / 2:
                            # Select the router origin AS
                            return iasn, utype + ALLPEER_SUCC

        # Apply vote heuristics
        # asns -- maximum vote getters, often one AS, but will contain all tied ASes
        # Check if single AS accounts for at least 3/4 of votes
        othermax = max(votes, key=votes.__getitem__)
        if votes[othermax] >= sum(votes.values()) * .75:
            # If so, select that AS
            asns = [othermax]
        else:
            # Otherwise, find vote ASes with relationship to a router interface AS
            votes_rels: List[int] = [
                vasn for vasn in votes if any(
                    vasn == iasn or self.bgp.rel(iasn, vasn) or self.as2org[iasn] == self.as2org[vasn]
                    for iasn in iasns
                )
            ]
            if DEBUG: print('Vote Rels: {}'.format(votes_rels))

            # If only IR origin ASes remain, use all votes. Otherwise, use relationship ASes and origins
            if len(votes_rels) <= len(iasns):
                asns = max_num(votes, key=votes.__getitem__)
                if DEBUG: print('ASNs: {}'.format(asns))
            else:
                asns = max_num(votes_rels, key=votes.__getitem__)

        # If single AS, select it
        if len(asns) == 1 and succs:
            asn = asns[0]
            utype += VOTE_SINGLE
        else:
            asn = None
            # Tiebreaker 1
            if len(router.succ) == 1:
                isucc = peek(router.succ)  # single subsequent interface
                sasn = self.iupdates.asn(isucc)  # annotation for subsequent interface
                if len(router.interfaces) == 1 and sasn == -1:
                    rasn = router.interfaces[0].asn
                    if self.bgp.peer_rel(rasn, isucc.asn):
                        return -1, 6000000
                # If annotation was used, is one of the tied ASes, and the subsequent interface has multiple incoming edges
                if sasn in succs and sasn in asns and len(isucc.pred) > 1:
                    if DEBUG: print('Pred Num: {}'.format(len(isucc.pred)))
                    asn = sasn  # select the subsequent interface annotation
                    utype += 5000000
            # Tiebreaker 2 -- use only when tiebreaker 1 does not select an AS (most of the time)
            if not asn:
                if DEBUG: print('Conesizes: {}'.format({a: self.bgp.conesize[a] for a in asns}))
                # First select from ASes that are both router origin ASes and subsequent ASes
                # Then select likely customer, based on smalles customer cone size
                asn = min(asns, key=lambda x: (not (x in sasn_origins[x] and x in succs), self.bgp.conesize[x], -x))
                utype += VOTE_TIE

        if asn not in iasns:
            overlap = iasns.keys() & succs.keys()
            if DEBUG: print('Overlap: {}'.format(overlap))
            if overlap:
                if DEBUG: print('Succs votes: {} < (2 * {}) / 3 = {}'.format(succs[asn], sum(succs.values()), (2 * sum(succs.values())) / 3))
                if succs[asn] < (2 * sum(succs.values())) / 3:
                    oasns = max_num(overlap, key=votes.__getitem__)
                    if len(oasns) == 1:
                        oasn = oasns[0]
                        if DEBUG: print('Orgs: {} != {}'.format(self.as2org[oasn], self.as2org[asn]))
                        if self.as2org[oasn] != self.as2org[asn]:
                            asn = oasn
                            utype += 1000000

        # Check for hidden AS
        # If no relationship between selected AS and an IR origin AS
        if iasns and all(asn != iasn and not self.bgp.rel(iasn, asn) for iasn in iasns):
            return self.hidden_asn(iasns, asn, utype, votes)
        return asn, utype

    def annotate_routers(self, routers: Collection[Router], increment=100000):
        pb = Progress(len(routers), 'Annotating routers', increment=increment)
        for router in pb.iterator(routers):
            asn, utype = self.annotate_router(router)
            self.rupdates.add_update(router, asn, self.as2org[asn], utype)

    def annotate_vrf_routers(self, routers: Collection[Router], increment=100000):
        pb = Progress(len(routers), 'Annotating forwarding routers', increment=increment)
        for router in pb.iterator(routers):
            asn, utype = self.annotate_router_vrf(router)
            self.rupdates.add_update_direct(router, asn, self.as2org[asn], utype)

    def annotate_interface(self, interface: Interface):
        edges: Dict[Router, int] = interface.pred
        if DEBUG:
            print('ASN: {}'.format(interface.asn))
            print('VRF: {}'.format(interface.vrf))
        votes = Counter()
        for rpred, num in edges.items():
            asn = self.rupdates.asn(rpred)
            if DEBUG: print('Router={}, RASN={}'.format(rpred.name, asn))
            votes[asn] += num
        if DEBUG: print('Votes: {}'.format(votes))
        if len(votes) == 1:
            return peek(votes), 1 if len(edges) > 1 else 0
        asns = max_num(votes, key=votes.__getitem__)
        if DEBUG: print('MaxNum: {}'.format(asns))
        rels = [asn for asn in asns if interface.asn == asn or self.bgp.rel(interface.asn, asn)]
        if not rels:
            rels = asns
        if DEBUG:
            print('Rels: {}'.format(rels))
            print('Sorted Rels: {}'.format(sorted(rels, key=lambda x: (
                x != interface.asn, -self.bgp.provider_rel(interface.asn, x), -self.bgp.conesize[x], x))))
        # asn = max(asns, key=lambda x: (x == interface.asn, bdrmapit.bgp.conesize[x], -x))
        # asn = min(rels, key=lambda x: (x != interface.asn, -self.bgp.provider_rel(interface.asn, x), -self.bgp.conesize[x], x))
        asn = min(rels, key=lambda x: (x != interface.asn, -self.bgp.conesize[x], x))
        utype = 1 if len(asns) == 1 and len(edges) > 1 else 2
        return asn, utype

    def annotate_interfaces(self, interfaces: Collection[Interface]):
        pb = Progress(len(interfaces), 'Adding links', increment=100000)
        for interface in pb.iterator(interfaces):
            if interface.asn >= 0:
                asn, utype = self.annotate_interface(interface)
                self.iupdates.add_update(interface, asn, self.as2org[asn], utype)

    def graph_refinement(self, routers: List[Router], interfaces: List[Interface], iterations=-1, vrfrouters: List[Router] = None):
        self.previous_updates = []
        iteration = 0
        while iterations < 0 or iteration < iterations:
            Progress.message('********** Iteration {:,d} **********'.format(iteration), file=sys.stderr)
            self.annotate_routers(routers)
            self.rupdates.advance()
            if vrfrouters:
                self.annotate_vrf_routers(vrfrouters)
            self.annotate_interfaces(interfaces)
            self.iupdates.advance()
            ru = dict(self.rupdates)
            iu = dict(self.iupdates)
            if (ru, iu) in self.previous_updates:
                break
            self.previous_updates.append((ru, iu))
            iteration += 1

    def sort_vrf(self, router: Router):
        nedges = len(router.succ)
        iasns = {interface.asn for interface in router.interfaces}
        iasn = min(iasns, key=lambda x: (self.bgp.conesize[x], -x))
        conesize = self.bgp.conesize[iasn]
        return -nedges, conesize, -iasn
