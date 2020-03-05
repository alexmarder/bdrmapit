import sys
from collections import Counter, defaultdict
from typing import Collection, List, Set, Dict, Union, Counter as TCounter, Optional

from traceutils.as2org.as2org import AS2Org
from traceutils.bgp.bgp import BGP
from traceutils.ixps import PeeringDB
from traceutils.progress.bar import Progress
from traceutils.utils.utils import max_num, peek

from algorithm import debug
from algorithm.debug import DebugMixin
from algorithm.firsthopmixin import FirstHopMixin
from algorithm.helpersmixin import HelpersMixin
from algorithm.lasthopsmixin import LastHopsMixin
from algorithm.utypes import HIDDEN_NOINTER, SINGLE_SUCC_4, ALLPEER_SUCC, VOTE_SINGLE, \
    VOTE_TIE, HIDDEN_INTER
from algorithm.vrfmixin import VRFMixin
from bdrmapit_parser.algorithm.updates_dict import Updates
from bdrmapit_parser.graph.construct import Graph
from bdrmapit_parser.graph.node import Router, Interface
from vrf.vrfedge import VRFEdge


class Bdrmapit(FirstHopMixin, LastHopsMixin, VRFMixin, DebugMixin, HelpersMixin):

    def __init__(self, graph: Graph, as2org: AS2Org, bgp: BGP, ixpasns=None, strict=True, skipua=False, hidden_reverse=True, norelpeer: Set[int]=None):
        self.graph = graph
        self.as2org = as2org
        self.bgp = bgp
        # self.peeringdb = peeringdb
        self.rupdates = Updates()
        self.iupdates = Updates()
        self.caches = Updates()
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
        self.norelpeer = norelpeer
        self.ixpasns = {} if ixpasns is None else ixpasns

    def router_heuristics(self, router: Router, isucc: Interface, origins: Set[int], iasns: TCounter[int]):
        rsucc: Router = isucc.router  # subsequent router
        rsucc_asn = self.rupdates.asn(rsucc)  # subsequent router AS annotation
        iupdate = self.iupdates[isucc]  # update for subsequent interface (interface annotation)

        # If subsequent interface is an IXP interface, use interface AS
        if isucc.asn <= -100:
            ixpasns = self.ixpasns.get(isucc.asn)
            if ixpasns:
                overlap = iasns.keys() & ixpasns
                if len(overlap) == 1:
                    return peek(overlap)
            return -1

        # If subsequent interface AS has no known origin, use subsequent router AS
        if isucc.asn == 0:
            return rsucc_asn if not self.skipua else -1

        # if iupdate:
        #     if iupdate.asn == -2:
        #         return -1

        if iupdate and self.as2org[rsucc_asn] == isucc.org:
        # if iupdate and rsucc_asn == isucc.asn:
            succ_asn = iupdate.asn
            succ_org = iupdate.org
            if succ_asn <= 0:
                succ_asn = isucc.asn
                succ_org = isucc.org
        else:
            succ_asn = isucc.asn
            succ_org = isucc.org
        if debug.DEBUG:
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
                    if debug.DEBUG:
                        print('\tThird party: Router={}, RASN={}'.format(rsucc.name, rsucc_asn))
                        print('\tAny origin-router rels? {}'.format(rsucc_asn in origins or self.any_rels(rsucc_asn, origins)))
                    if rsucc_asn in origins or self.any_rels(rsucc_asn, origins):
                        # If here, some origin AS matches the subsequent router's AS annotation
                        # Or, some origin AS directly interconnects with the subsequent routers AS annotation

                        # Number of destination in subsequent interface origin AS customer cone
                        s_conesize = len(router.dests & self.bgp.cone[succ_asn])
                        # Number of destination in subsequent router AS annotation customer cone
                        r_conesize = len(router.dests & self.bgp.cone[rsucc_asn])
                        if debug.DEBUG:
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
                        if debug.DEBUG: print('Testing')
                        # return rsucc_asn
                        third = True
        if third:
            # Third party was detected!
            rsucc_cone = self.bgp.cone[rsucc_asn]  # subsequent router AS annotation customer cone
            if debug.DEBUG:
                if len(router.dests) <= 5:
                    print('\tDests: {}'.format(router.dests))
                if len(rsucc_cone) <= 5:
                    print('\tCone: {}'.format(rsucc_cone))
            if all(dasn == rsucc_asn or dasn in rsucc_cone for dasn in router.dests):
                # If here, all destination ASes are in the customer cone of the subsequent router's AS annotation
                return rsucc_asn
            if debug.DEBUG:
                for origin in origins:
                    print('\tOrigin {}: RSUCC overlap {} ? SUCC overlap {}'.format(origin, len(router.dests & rsucc_cone), len(router.dests & self.bgp.cone[origin])))
                # print('\tASes not in customer cone for {}'.format(rsucc_asn))
                # for dasn in router.dests:
                #     if dasn not in rsucc_cone and dasn != rsucc_asn:
                #         print('\t\t{}, in succ ASN cone {}'.format(dasn, dasn in self.bgp.cone[succ_asn]))
            # Otherwise, ignore vote
            return -1

        # TODO: Figure out something better to do here
        if succ_asn <= 0 or (rsucc_asn > 0 and self.as2org[rsucc_asn] != isucc.org):
        # if succ_asn <= 0 or (rsucc_asn > 0 and rsucc_asn != isucc.asn):
            if debug.DEBUG:
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
            if debug.DEBUG: print('Hidden: {}'.format(intasn))

        # If there is no intersection, check for provider of interface AS who is customer of selected AS
        elif not intersection and self.hidden_reverse:
            intersection = self.multi_providers(iasns) & self.bgp.customers[asn]
            if len(intersection) == 1:
                intasn = peek(intersection)
                if debug.DEBUG: print('Hidden Reversed: {}'.format(intasn))

        # If a hidden AS was selected
        if intasn is not None:
            interorg = self.as2org[intasn]
            # If the hidden AS is a sibling of an AS which received a vote (interface or subsequent AS),
            #  use the selected AS. I think it suggests the selected AS actually has a relationship.
            if interorg in {self.as2org[vasn] for vasn in votes}:
                return asn, HIDDEN_NOINTER + utype
            return intasn, HIDDEN_INTER + utype

        if debug.DEBUG: print('Missing: {}-{}'.format(iasns, asn))
        if self.strict:
            return max(iasns, key=lambda x: (votes[x], -self.bgp.conesize[x], x)), HIDDEN_NOINTER + utype
        else:
            return asn, HIDDEN_NOINTER + utype

    def annotate_router(self, router: Router, **kwargs):
        isucc: Union[Interface, VRFEdge]
        utype: int = 0

        # Router origin ASes
        iasns: TCounter[int] = Counter(interface.asn for interface in router.interfaces if interface.asn > 0)
        if debug.DEBUG:
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
            if debug.DEBUG: print('Succ={}, ASN={}, Origins={} RSucc={}'.format(isucc.addr, isucc.asn, origins, isucc.router.name))
            succ_asn = self.router_heuristics(router, isucc, origins, iasns)  # AS vote for the subsequent interface
            if debug.DEBUG: print('Heuristic: {}'.format(succ_asn))
            # If vote is useful
            if succ_asn > 0:
                succs[succ_asn] += 1  # record vote
                sasn_origins[succ_asn].update(origins)  # record origin ASes seen before interface
        if debug.DEBUG: print('Succs: {}'.format(succs))

        # Deal specially with cases where there is only a single subsequent AS, or subsequent ORG
        # Multihomed exception
        if iasns and len(succs) == 1 or len({self.as2org[sasn] for sasn in succs}) == 1:
            # Subsequent AS
            sasn = peek(succs) if len(succs) == 1 else max(succs, key=lambda x: (self.bgp.conesize[x], -x))
            # Subsequent AS is not in link origin ASes and is a customer of a link origin AS
            if sasn not in sasn_origins[sasn]:
                if sasn in self.multi_customers(sasn_origins[sasn]):
                    if debug.DEBUG: print('Provider: {}->{}'.format(sasn_origins[sasn], sasn))
                    return sasn, utype + SINGLE_SUCC_4

        # Create votes counter and add interface AS
        votes = succs + iasns
        if debug.DEBUG: print('Votes: {}'.format(votes))
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
                    # if all(self.bgp.rel(iasn, sasn) for sasn in succs):
                    if sum(self.bgp.peer_rel(iasn, sasn) or (self.norelpeer and iasn in self.norelpeer and not self.bgp.rel(iasn, sasn)) for sasn in succs) >= len(succs) * .85:
                        if debug.DEBUG:
                            print('All peers or norels: True')
                        # Make sure its votes are not dwarfed by subsequent AS
                        if votes[iasn] > max(votes.values()) / 2:
                            # Select the router origin AS
                            return iasn, utype + ALLPEER_SUCC
                        if votes[iasn] > max(votes.values()) / 4 and sum(self.bgp.peer_rel(iasn, sasn) for sasn in succs) >= 2:
                            return iasn, utype + ALLPEER_SUCC
                        if self.norelpeer is not None and iasn in self.norelpeer and votes[iasn] > max(votes.values()) / 4 and len(succs) >= 3:
                            return iasn, utype + ALLPEER_SUCC
                    elif debug.DEBUG:
                        print([sasn for sasn in succs if not (self.bgp.peer_rel(iasn, sasn) or (self.norelpeer and iasn in self.norelpeer and not self.bgp.rel(iasn, sasn)))])

        # Apply vote heuristics
        # asns -- maximum vote getters, often one AS, but will contain all tied ASes
        # Check if single AS accounts for at least 3/4 of votes
        othermax = max(votes, key=votes.__getitem__)
        if votes[othermax] >= sum(votes.values()) * .75:
            # If so, select that AS
            asns = [othermax]
        else:
            # Otherwise, find vote ASes with relationship to a router interface AS
            # try:
            votes_rels: List[int] = [
                vasn for vasn in votes if any(
                    (self.norelpeer and iasn in self.norelpeer) or vasn == iasn or self.bgp.rel(iasn, vasn) or self.as2org[iasn] == self.as2org[vasn]
                    for iasn in iasns
                )
            ]
            # except TypeError:
            #     print(router.name)
            #     print(iasns)
            if debug.DEBUG: print('Vote Rels: {}'.format(votes_rels))

            # If only IR origin ASes remain, use all votes. Otherwise, use relationship ASes and origins
            if len(votes_rels) <= len(iasns):
                asns = max_num(votes, key=votes.__getitem__)
                if debug.DEBUG: print('ASNs: {}'.format(asns))
            else:
                asns = max_num(votes_rels, key=votes.__getitem__)

        # If single AS, select it
        if len(asns) == 1 and succs:
            asn = asns[0]
            utype += VOTE_SINGLE
        else:
            asn = None
            # Tiebreaker 0
            # print('here')
            # if asns:
            #     for casn in asns:
            #         providers = self.bgp.providers[casn]
            #         if debug.DEBUG:
            #             print(casn, providers)
            #         if all(pasn in providers for pasn in asns if pasn != casn):
            #             asn = casn
            #             utype += 700000
            #             break
            # Tiebreaker 1
            if asn is None and len(router.succ) == 1 and router.nexthop:
                isucc = peek(router.succ)  # single subsequent interface
                sasn = self.iupdates.asn(isucc)  # annotation for subsequent interface
                if len(router.interfaces) == 1 and sasn == -1:
                    rasn = router.interfaces[0].asn
                    if self.bgp.peer_rel(rasn, isucc.asn) or not self.bgp.rel(rasn, isucc.asn):
                        return -1, 6000000
                # If annotation was used, is one of the tied ASes, and the subsequent interface has multiple incoming edges
                if sasn in succs and sasn in asns and len(isucc.pred) > 1:
                    if debug.DEBUG: print('Pred Num: {}'.format(len(isucc.pred)))
                    asn = sasn  # select the subsequent interface annotation
                    utype += 5000000
            if not asn and len(router.succ) == 1:
                if len(router.interfaces) == 1:
                    isucc = peek(router.succ)  # single subsequent interface
                    sasn = self.iupdates.asn(isucc)  # annotation for subsequent interface
                    if sasn == -1:
                        sasn = isucc.asn
                    rasn = router.interfaces[0].asn
                    reltype = self.bgp.reltype(rasn, sasn)
                    if debug.DEBUG: print('One interface: {} -- {} == {}'.format(rasn, sasn, reltype))
                    if reltype != 1 and reltype != 2:
                        if sasn in router.dests and rasn not in router.dests:
                            asn = sasn
                            utype += 16000
            # Tiebreaker 2 -- use only when tiebreaker 1 does not select an AS (most of the time)
            if not asn:
                if debug.DEBUG: print('Conesizes: {}'.format({a: self.bgp.conesize[a] for a in asns}))
                # First select from ASes that are both router origin ASes and subsequent ASes
                # Then select likely customer, based on smalles customer cone size
                asn = min(asns, key=lambda x: (not (x in sasn_origins[x] and x in succs), self.bgp.conesize[x], -x))
                utype += VOTE_TIE

        if asn not in iasns:
            overlap = iasns.keys() & succs.keys()
            if debug.DEBUG: print('Overlap: {}'.format(overlap))
            if overlap:
                if debug.DEBUG: print('Succs votes: {} < (2 * {}) / 3 = {}'.format(succs[asn], sum(succs.values()), (2 * sum(succs.values())) / 3))
                if succs[asn] < (2 * sum(succs.values())) / 3:
                    oasns = max_num(overlap, key=votes.__getitem__)
                    if len(oasns) == 1:
                        oasn = oasns[0]
                        if debug.DEBUG: print('Orgs: {} != {}'.format(self.as2org[oasn], self.as2org[asn]))
                        if self.as2org[oasn] != self.as2org[asn]:
                            asn = oasn
                            utype += 1000000

        # if not router.nexthop and iasns and asn not in iasns and all(self.bgp.peer_rel(iasn, asn) or not self.bgp.rel(iasn, asn) for iasn in iasns):
        #     asn = min(iasns, key=lambda x: (not (x in sasn_origins[x] and x in succs), self.bgp.conesize[x], -x))
        #     utype += 7000000

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
        if debug.DEBUG:
            print('ASN: {}'.format(interface.asn))
            print('VRF: {}'.format(interface.vrf))
        votes = Counter()
        for rpred, num in edges.items():
            asn = self.rupdates.asn(rpred)
            if debug.DEBUG: print('Router={}, RASN={}'.format(rpred.name, asn))
            votes[asn] += num
        if debug.DEBUG: print('Votes: {}'.format(votes))
        if len(votes) == 1:
            asn = peek(votes)
            utype = 1 if len(edges) > 1 else 0
        else:
            asns = max_num(votes, key=votes.__getitem__)
            if debug.DEBUG: print('MaxNum: {}'.format(asns))
            rels = [asn for asn in asns if interface.asn == asn or self.bgp.rel(interface.asn, asn)]
            if not rels:
                rels = asns
            if debug.DEBUG:
                print('Rels: {}'.format(rels))
                print('Sorted Rels: {}'.format(sorted(rels, key=lambda x: (
                    x != interface.asn, -self.bgp.provider_rel(interface.asn, x), -self.bgp.conesize[x], x))))
            # asn = max(asns, key=lambda x: (x == interface.asn, bdrmapit.bgp.conesize[x], -x))
            # asn = min(rels, key=lambda x: (x != interface.asn, -self.bgp.provider_rel(interface.asn, x), -self.bgp.conesize[x], x))
            asn = min(rels, key=lambda x: (x != interface.asn, -self.bgp.conesize[x], x))
            utype = 1 if len(asns) == 1 and len(edges) > 1 else 2
        if asn == -1:
            return -2, 2
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
