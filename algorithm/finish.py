from typing import Set

from traceutils.as2org.as2org import AS2Org
from traceutils.bgp.bgp import BGP
from traceutils.progress.bar import Progress

from bdrmapit_parser.algorithm.bdrmapit import Bdrmapit


def set_dests(bdrmapit: Bdrmapit, increment=100000):
    as2org: AS2Org = bdrmapit.as2org
    bgp: BGP = bdrmapit.bgp
    pb = Progress(len(bdrmapit.graph.interfaces), 'Modifying interface dests', increment=increment)
    for interface in pb.iterator(bdrmapit.graph.interfaces.values()):
        idests: Set[int] = interface.dests
        if idests:
            orgs = {as2org[a] for a in idests}
            if len(orgs) == 2 and interface.asn in idests:
                if max(idests, key=lambda x: (bgp.conesize[x], -x)) == interface.asn:
                    idests.discard(interface.asn)
    pb = Progress(len(bdrmapit.graph.routers), 'Setting destinations', increment=increment)
    for router in pb.iterator(bdrmapit.graph.routers.values()):
        for interface in router.interfaces:
            router.dests.update(interface.dests)
