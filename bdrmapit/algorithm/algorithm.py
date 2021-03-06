import sys
from collections import Counter, defaultdict
from typing import Collection, List, Set, Dict, Union, Counter as TCounter, Optional

from traceutils.as2org.as2org import AS2Org
from traceutils.bgp.bgp import BGP
from traceutils.progress.bar import Progress
from traceutils.utils.utils import max_num, peek

from bdrmapit.algorithm import debug
from bdrmapit.algorithm.debug import DebugMixin
from bdrmapit.algorithm.firsthopmixin import FirstHopMixin
from bdrmapit.algorithm.helpersmixin import HelpersMixin
from bdrmapit.algorithm.lasthopsmixin import LastHopsMixin
from bdrmapit.algorithm.regexmixin import RegexMixin
from bdrmapit.algorithm.utypes import HIDDEN_NOINTER, SINGLE_SUCC_4, ALLPEER_SUCC, VOTE_SINGLE, \
    VOTE_TIE, HIDDEN_INTER
from bdrmapit.algorithm.vrfmixin import VRFMixin
from bdrmapit.algorithm.updates_dict import Updates
from bdrmapit.graph.construct import Graph
from bdrmapit.graph.node import Router, Interface
from bdrmapit.vrf.vrfedge import VRFEdge


class Bdrmapit(FirstHopMixin, LastHopsMixin, VRFMixin, RegexMixin, DebugMixin, HelpersMixin):

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
                if debug.DEBUG: print('IXP ASNs: {}'.format(len(ixpasns)))
                overlap = iasns.keys() & ixpasns
                if len(overlap) == 1:
                    return peek(overlap)
            return -1

        # If subsequent interface AS has no known origin, use subsequent router AS
        if isucc.asn == 0:
            return rsucc_asn if not self.skipua else -1

        if iupdate and self.as2org[rsucc_asn] == isucc.org:
            succ_asn = iupdate.asn
            succ_org = iupdate.org
            if succ_asn <= 0:
                succ_asn = isucc.asn
                succ_org = isucc.org
            # elif isucc.asn in router.dests and all(iasn <= 0 for iasn in origins):
            #     succ_asn = isucc.asn
            #     succ_org = isucc.org
        else:
            succ_asn = isucc.asn
            succ_org = isucc.org
        if debug.DEBUG: print('\tASN={}, RASN={}, IUpdate={} VRF={}'.format(isucc.asn, rsucc_asn, succ_asn, router.vrf))

        # Third party stuff
        third = False
        if any(iasn > 0 for iasn in origins) and not any(isucc.org == self.as2org[iasn] for iasn in origins):
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
            # Otherwise, ignore vote
            return -1

        # TODO: Figure out something better to do here
        if succ_asn <= 0 or (rsucc_asn > 0 and self.as2org[rsucc_asn] != isucc.org):
            if debug.DEBUG:
                if succ_asn != isucc.asn:
                    print('ugh')
            succ_asn = isucc.asn
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

    def isnorelpeer(self, iasn):
        return bool(self.norelpeer and iasn in self.norelpeer)

    def annotate_router(self, router: Router, first=False, **kwargs):
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
        sorigins = Counter(isucc.asn for isucc in router.succ)
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

        # Create votes counter and add interface AS
        votes = succs + iasns
        if debug.DEBUG: print('Votes: {}'.format(votes))
        if not succs:
            # return -1, -1
            return self.annotate_lasthop(router)

        # if iasns and succs and any(sasn in iasns or sasn in self.multi_customers(sasn_origins[sasn]) for sasn in succs):
        #     maxrels = {}
        #     for asn in votes:
        #         rels = sum(bool(asn == dasn or self.bgp.rel(asn, dasn) or dasn in self.bgp.cone[asn]) for dasn in router.dests)
        #         maxrels[asn] = rels
        #     if debug.DEBUG:
        #         print('Max Rels: {}'.format(maxrels))
        #     if maxrels:
        #         asn, num = max(maxrels.items(), key=lambda x: x[1])
        #         if asn in iasns:
        #             if num > maxrels[max(succs, key=maxrels.__getitem__)] + 2:
        #                 return asn, 46

        if len(iasns) == 1 and len(succs) == 1:
            iasn = peek(iasns)
            sasn = peek(succs)
            if iasns[iasn] == succs[sasn]:
                if self.bgp.peer_rel(iasn, sasn) or (self.norelpeer and iasn in self.norelpeer and not self.bgp.rel(iasn, sasn)):
                    return sasn, 5600

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

        # Multiple Peers Exception
        # More than 1 subsequent AS and exactly one router origin AS
        if len(succs) > 1 and len(iasns) == 1:
            iasn = peek(iasns)
            # Origin AS is not also a subsequent AS
            if iasn not in succs:
                # All subsequent ASes are peers of the single origin AS
                peerrels = {self.as2org[sasn] for sasn in succs if self.bgp.peer_rel(iasn, sasn) or (self.norelpeer and iasn in self.norelpeer and not self.bgp.rel(iasn, sasn))}
                # numrels = sum(1 for sasn in succs if self.bgp.peer_rel(iasn, sasn) or (self.norelpeer and iasn in self.norelpeer and not self.bgp.rel(iasn, sasn)))
                numrels = len(peerrels)
                if debug.DEBUG: print('Peers: {} >= {}'.format(numrels, len(succs) * .85))
                if numrels >= len(succs) * .85:
                    if debug.DEBUG:
                        print('All peers or norels: True')
                        print('IASN: {:,d}, Max Vote: {:,d}'.format(votes[iasn], max(votes.values())))
                    # Make sure its votes are not dwarfed by subsequent AS
                    if votes[iasn] > max(votes.values()) / 2:
                        if first:
                            return -1, utype + ALLPEER_SUCC
                        # Select the router origin AS
                        return iasn, utype + ALLPEER_SUCC
                    if debug.DEBUG: print('{:,d} > {:.1f}'.format(votes[iasn], max(votes.values()) / 4))
                    if votes[iasn] > max(votes.values()) / 4 and sum(self.bgp.peer_rel(iasn, sasn) for sasn in succs) >= 2:
                        if first:
                            return -1, utype + ALLPEER_SUCC
                        return iasn, utype + ALLPEER_SUCC
                    if self.norelpeer is not None and iasn in self.norelpeer and votes[iasn] > max(votes.values()) / 4 and len(succs) >= 3:
                        if first:
                            return -1, utype + ALLPEER_SUCC
                        return iasn, utype + ALLPEER_SUCC
                if len(succs) > 2:
                    numrels = sum(self.bgp.rel(iasn, sasn) for sasn in succs)
                    if debug.DEBUG: print('Rels: {} >= {}'.format(numrels, len(succs) * .9))
                    if numrels >= len(succs):
                        if votes[iasn] > max(votes.values()) / 2:
                            # Select the router origin AS
                            return iasn, utype + ALLPEER_SUCC
                        if votes[iasn] > max(votes.values()) / 4 and sum(
                                self.bgp.peer_rel(iasn, sasn) for sasn in succs) >= 2:
                            return iasn, utype + ALLPEER_SUCC
                        if self.norelpeer is not None and iasn in self.norelpeer and votes[iasn] > max(
                                votes.values()) / 4 and len(succs) >= 3:
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
            votes_rels = []
            for vasn in votes:
                if any(self.isnorelpeer(iasn) or vasn == iasn or self.bgp.rel(iasn, vasn) or self.as2org[iasn] == self.as2org[vasn] for iasn in iasns):
                    votes_rels.append(vasn)
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
            # Tiebreaker 1
            if asn is None and len(router.succ) == 1 and router.nexthop:
                isucc = peek(router.succ)  # single subsequent interface
                sasn = self.iupdates.asn(isucc)  # annotation for subsequent interface
                if len(router.interfaces) == 1 and sasn == -1:
                    rasn = router.interfaces[0].asn
                    if self.bgp.peer_rel(rasn, isucc.asn) or (self.isnorelpeer(rasn) and not self.bgp.rel(rasn, isucc.asn)):
                        return -1, 6000000
                # If annotation was used, is one of the tied ASes, and the subsequent interface has multiple incoming edges
                # if sasn in succs and sasn in asns and len(isucc.pred) > 1 and (True or not any(iasn > 0 and iasn in router.dests for iasn in sasn_origins[sasn])):
                if sasn in succs and sasn in asns and len(isucc.pred) > 1:
                    if debug.DEBUG: print('Pred Num: {}'.format(len(isucc.pred)))
                    asn = sasn  # select the subsequent interface annotation
                    utype += 5000000
                    if len(router.interfaces) == 1:
                        iasn = router.interfaces[0].asn
                        # if iasn > 0 and not (self.norelpeer and iasn in self.norelpeer) and not self.bgp.rel(iasn, sasn):
                        #     asn = None
                        #     utype = 0
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
                asn = min(asns, key=lambda x: (not (x in sasn_origins[x] and x in sorigins), x not in router.dests, self.bgp.conesize[x], -x))
                utype += VOTE_TIE

        if asn not in iasns:
            overlap = iasns.keys() & sorigins.keys()
            if debug.DEBUG: print('Overlap: {}'.format(overlap))
            if len(overlap) == 1:
                if debug.DEBUG: print('Succs votes: {} < (2 * {}) / 3 = {}'.format(sorigins[asn], sum(sorigins.values()), (2 * sum(sorigins.values())) / 3))
                if succs[asn] < (2 * sum(sorigins.values())) / 3:
                    oasns = max_num(overlap, key=votes.__getitem__)
                    if len(oasns) == 1:
                        oasn = oasns[0]
                        if debug.DEBUG: print('Orgs: {} != {}'.format(self.as2org[oasn], self.as2org[asn]))
                        if self.as2org[oasn] != self.as2org[asn]:
                            asn = oasn
                            utype += 1000000

        # Check destination ASes
        # if not iasns and not router.nexthop and sum(succs.values()) <= 1:
        #     dasn, _ = self.annotate_lasthop(router)
        #     if debug.DEBUG:
        #         print('Curr ASN: {}'.format(asn))
        #         print('Last hop: {}'.format(dasn))
        #     if dasn != asn:
        #         if debug.DEBUG: print('{} in cone[{}]'.format(asn, dasn, asn in self.bgp.cone[dasn]))
        #         if asn in self.bgp.cone[dasn]:
        #             asn = dasn
        #             utype = 17000

        # Check for hidden AS
        # If no relationship between selected AS and an IR origin AS
        if iasns and all(asn != iasn and not self.bgp.rel(iasn, asn) for iasn in iasns):
            # for iasn in iasns:
            #     if iasn > 0 and iasn in router.dests:
            #         return iasn, 43
            if not router.dests & votes.keys():
                dasns = {dasn for dasn in router.dests if any(iasn == dasn or self.bgp.rel(iasn, dasn) for iasn in iasns)}
                if debug.DEBUG:
                    print('DASNs: {}'.format(dasns))
                if len(dasns) == 1:
                    return peek(dasns), 42
            return self.hidden_asn(iasns, asn, utype, votes)
        return asn, utype

    def annotate_routers(self, routers: Collection[Router], usehints=False, use_provider=False, first=False, increment=100000):
        pb = Progress(len(routers), 'Annotating routers', increment=increment)
        for router in pb.iterator(routers):
            asn = -1
            utype = -1
            if usehints and router.hints:
                asn, utype = self.annotate_router_hint(router, use_provider=use_provider)
            if asn <= 0:
                asn, utype = self.annotate_router(router, first=first)
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
            if debug.DEBUG: print('Router={}, RASN={}, ASN={}'.format(rpred.name, asn, rpred.interfaces[0].asn))
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

    def graph_refinement(self, routers: List[Router], interfaces: List[Interface], iterations=-1, vrfrouters: List[Router] = None, usehints=False, use_provider=False):
        self.previous_updates = []
        iteration = 0
        while iterations < 0 or iteration < iterations:
            Progress.message('********** Iteration {:,d} **********'.format(iteration), file=sys.stderr)
            self.annotate_routers(routers, first=(iteration == 0), usehints=usehints, use_provider=use_provider)
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
