from collections import Counter
from typing import Set, Optional, Collection

from traceutils.as2org.as2org import AS2Org
from traceutils.bgp.bgp import BGP
from traceutils.progress import Progress
from traceutils.utils.utils import peek

from bdrmapit.algorithm import debug
from bdrmapit.algorithm.regexmixin import RegexMixin
from bdrmapit.algorithm.utypes import NODEST, MISSING_NOINTER, HEAPED
from bdrmapit.algorithm.updates_dict import Updates
from bdrmapit.graph.construct import Graph
from bdrmapit.graph.node import Router


class LastHopsMixin(RegexMixin):

    rupdates: Optional[Updates] = None
    bgp: Optional[BGP] = None
    as2org: Optional[AS2Org] = None
    graph: Optional[Graph] = None
    strict = False
    lasthops: Optional[Collection[Router]] = None

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

    def annotate_lasthop_nodests(self, iasns):
        if debug.DEBUG: print('No dests')
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
            if debug.DEBUG:
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
        if debug.DEBUG:
            for iasn in iasns:
                print('{}: {}'.format(iasn, iasns[iasn]))
        # Select the most frequent origin AS, break ties with smallest customer cone size
        return max(iasns, key=lambda x: (iasns[x], -self.bgp.conesize[x], x)), 5

    def annotate_lasthop_norels(self, dests, iasns):
        if self.strict:
            return max(iasns, key=lambda x: (iasns[x], -self.bgp.conesize[x], x)), NODEST
        if iasns:
            if debug.DEBUG: print('IASNs: {}'.format(iasns))
            if debug.DEBUG:
                print('Providers: {}'.format(self.multi_providers(dests)))
            intersection = self.multi_providers(dests) & self.multi_customers(iasns)
            if len(intersection) == 1:
                if debug.DEBUG: print('Inter Cust: {}'.format(intersection))
                return peek(intersection), 10000
            # intersection = self.multi_providers(dests) & self.multi_peers(iasns)
            # if len(intersection) == 1:
            #     return peek(intersection), 30000
            intersection = self.multi_customers(dests) & self.multi_providers(iasns)
            if len(intersection) == 1:
                return peek(intersection), 20000
        # asn = min(dests, key=lambda x: (self.bgp.conesize[x], -x))
        asn = max(dests, key=lambda x: (self.bgp.conesize[x], -x))
        return asn, MISSING_NOINTER

    def annotate_lasthop(self, router: Router, dests=None):
        if dests is None:
            dests = router.dests
        iasns = Counter(interface.asn for interface in router.interfaces if interface.asn > 0)
        if debug.DEBUG:
            print('IASNs: {}'.format(iasns))
            print('Dests: {}'.format(dests))
        # No destination ASes
        if len(router.dests) == 0 or all(dest <= 0 for dest in router.dests):
            return self.annotate_lasthop_nodests(iasns)
        # Use overlapping ASes if available
        overlap = iasns.keys() & dests
        if debug.DEBUG: print('Dest IASN intersection: {}'.format(overlap))
        if overlap:
            if len(overlap) == 1:
                return peek(overlap), HEAPED
            return min(overlap, key=lambda x: (self.bgp.conesize[x], -x)), HEAPED
        # No overlapping ASes, use relationship ASes
        rels = {dasn for dasn in dests if self.any_rels(dasn, iasns)}
        if debug.DEBUG:
            print({(dasn, self.bgp.conesize[dasn]) for dasn in dests})
        if debug.DEBUG: print('Rels: {}'.format(rels))
        if rels:
            # Select overlapping or relationship AS with largest customer cone
            # return min(rels, key=lambda x: (self.bgp.conesize[x], -x)), HEAPED
            if len(rels) >= 4:
                return max(iasns, key=lambda x: sum(self.bgp.rel(x, dasn) for dasn in rels)), HEAPED
            maxasn = max(rels, key=lambda x: (self.bgp.conesize[x], -x))
            if len(dests - self.bgp.cone[maxasn]) > 4:
                if debug.DEBUG:
                    print('Uncovered dests for {}: {}'.format(maxasn, dests - self.bgp.cone[maxasn]))
                return max(iasns, key=lambda x: sum(self.bgp.rel(x, dasn) for dasn in rels)), HEAPED
            return maxasn, HEAPED
            # return max(rels, key=lambda x: (len(self.bgp.cone[x] & dests), -x)), HEAPED
        # No relationship between any origin AS and any destination AS
        return self.annotate_lasthop_norels(dests, iasns)

    def annotate_lasthops(self, routers=None, usehints=False, use_provider=False):
        if routers is None:
            routers = self.lasthops
        pb = Progress(len(routers), message='Last Hops', increment=100000)
        for router in pb.iterator(routers):
            asn = -1
            utype = -1
            if usehints and router.hints:
                asn, utype = self.annotate_router_hint(router, use_provider=use_provider)
            if asn <= 0:
                asn, utype = self.annotate_lasthop(router)
            self.rupdates.add_update_direct(router, asn, self.as2org[asn], utype)
