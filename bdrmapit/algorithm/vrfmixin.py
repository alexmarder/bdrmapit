from collections import Counter, defaultdict
from typing import Optional, List, Set

from traceutils.as2org.as2org import AS2Org
from traceutils.bgp.bgp import BGP
from traceutils.utils.utils import max_num

from bdrmapit.algorithm import debug
from bdrmapit.algorithm.utypes import VOTE_SINGLE, VOTE_TIE
from bdrmapit.algorithm.updates_dict import Updates
from bdrmapit.graph.node import Router
from bdrmapit.vrf.vrfedge import VRFEdge, VType


class VRFMixin:

    rupdates: Optional[Updates] = None
    bgp: Optional[BGP] = None
    as2org: Optional[AS2Org] = None

    def vrf_heuristics(self, edge: VRFEdge, origins: Set[int]):
        rsucc: Router = edge.node
        vtype = edge.vtype
        if debug.DEBUG: print('VType={}'.format(vtype.name))
        for iface in rsucc.interfaces:
            if iface.asn > 0 and iface.asn in origins:
                return iface.asn
        rsucc_asn = self.rupdates.asn(rsucc)
        return rsucc_asn

    def annotate_router_vrf(self, router: Router):
        edge: VRFEdge
        utype: int = 0

        iasns = Counter(interface.asn for interface in router.interfaces if interface.asn > 0)
        if debug.DEBUG:
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
            if debug.DEBUG: print('Succ={}, ASN={}, VRF={}'.format(edge.node.name, self.rupdates[edge.node], edge.node.vrf))
            # succ_asn = self.vrf_heuristics(edge, origins, iasns)
            succ_asn = self.vrf_heuristics(edge, origins)
            if vtype is None:
                vtype = edge.vtype
            elif vtype.value != edge.vtype.value:
                vtype = VType.both
            if debug.DEBUG: print('Heuristic: {}'.format(succ_asn))
            if succ_asn > 0:
                succs[succ_asn] += 1
                sasn_origins[succ_asn].update(origins)
                if not edge.node.vrf:
                    nonvrf[succ_asn] += 1
        if debug.DEBUG:
            print('Succs: {}'.format(succs))
            print('VType: {}'.format(vtype))

        # Create votes counter and add interface AS
        if debug.DEBUG: print('NonVRF: {}'.format(nonvrf))
        if nonvrf:
            votes = nonvrf
            utype += 50000
        else:
            votes = succs + iasns
        if debug.DEBUG: print('Votes: {}'.format(votes))
        if not votes:
            return -1, -1

        votes_rels: List[int] = [vasn for vasn in votes if any(
            vasn == iasn or self.bgp.rel(iasn, vasn) or self.as2org[iasn] == self.as2org[vasn] for iasn in iasns)]
        if debug.DEBUG: print('Vote Rels: {}'.format(votes_rels))
        if len(votes_rels) < 2:
            asns = max_num(votes, key=votes.__getitem__)
            if debug.DEBUG: print('ASNs: {}'.format(asns))
        else:
            for vasn in list(votes):
                if vasn not in votes_rels:
                    for vr in votes_rels:
                        if self.as2org[vr] == self.as2org[vasn]:
                            votes[vr] += votes.pop(vasn, 0)
            asns = max_num(votes_rels, key=votes.__getitem__)
            othermax = max(votes, key=votes.__getitem__)
            if debug.DEBUG:
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

    def sort_vrf(self, router: Router):
        nedges = len(router.succ)
        iasns = {interface.asn for interface in router.interfaces}
        iasn = min(iasns, key=lambda x: (self.bgp.conesize[x], -x))
        conesize = self.bgp.conesize[iasn]
        return -nedges, conesize, -iasn
