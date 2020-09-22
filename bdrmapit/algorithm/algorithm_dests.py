from collections import Counter, defaultdict
from typing import List, Union, Counter as TCounter

from traceutils.utils.utils import max_num, peek

from bdrmapit.algorithm import Bdrmapit, SINGLE_SUCC_4, ALLPEER_SUCC, VOTE_TIE, VOTE_SINGLE
from bdrmapit.bdrmapit_parser import Router, Interface
from bdrmapit.vrf.vrfedge import VRFEdge

class BdrmapitDests(Bdrmapit):

    def annotate_router(self, router: Router):
        from bdrmapit.algorithm import DEBUG
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

        # # Multiple Peers Exception
        # # More than 1 subsequent AS
        # if len(succs) > 1:
        #     # Exactly one router origin AS
        #     if len(iasns) == 1:
        #         iasn = peek(iasns)
        #         # Origin AS is not also a subsequent AS
        #         if iasn not in succs:
        #             votetotal = sum(votes.values())
        #             print({k: v / votetotal for k, v in votes.items()})
        #             if not any(v / votetotal > .3 for v in votes.values()):
        #                 if 

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
                if DEBUG: print('Succs votes: {} < {} / 2 = {}'.format(succs[asn], sum(succs.values()), sum(succs.values()) / 2))
                if succs[asn] < sum(succs.values()) / 2:
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
