from typing import Optional, Collection, Set

from traceutils.as2org.as2org import AS2Org
from traceutils.bgp.bgp import BGP
from traceutils.utils.utils import peek

from bdrmapit_parser.algorithm.updates_dict import Updates
from bdrmapit_parser.graph.construct import Graph
from bdrmapit_parser.graph.node import Router


class LastHopsMixin:

    rupdates: Optional[Updates] = None
    bgp: Optional[BGP] = None
    as2org: Optional[AS2Org] = None
    graph: Optional[Graph] = None
    strict = False
    lasthops: Optional[Collection[Router]] = None

    def annotate_lasthop_hint(self, router: Router, hints: Set[int]):
        iasns = {interface.asn for interface in router.interfaces if interface.asn > 0}
        intersection = (iasns | router.dests) & hints
        if len(intersection) == 1:
            return peek(intersection)
        elif len(intersection) > 2:
            return -1
        return 0

    def annotate_router_hint(self, router: Router, hints: Set[int]):
        iasns = {interface.asn for interface in router.interfaces if interface.asn > 0}
        sasns = {succ.asn for succ in router.succ if succ.asn > 0}
        intersection = (iasns | sasns | router.dests) & hints
        if len(intersection) == 1:
            return peek(intersection)
        elif len(intersection) > 2:
            return -1
        return 0
