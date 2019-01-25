import heapq as hq
from typing import List, Set

from traceutils.progress.bar import Progress
from traceutils.utils.utils import peek

from bdrmapit_parser.algorithm.bdrmapit import Bdrmapit
from bdrmapit_parser.graph.node import Router, Interface

NOTIMPLEMENTED = 0
NODEST = 1
MODIFIED = 3
SINGLE = 4
SINGLE_MODIFIED = 5
HEAPED = 6
HEAPED_MODIFIED = 7
MISSING_NOINTER = 10
MISSING_INTER = 9


DEBUG = False


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


def heaptest(bdrmapit: Bdrmapit, rdests: Set[int], interface: Interface):
    heap = []
    for a in rdests:
        hq.heappush(heap, (bdrmapit.bgp.conesize[a], -a, a))
    original_min = heap[0][-1]
    while heap:
        dest = hq.heappop(heap)[-1]
        if interface.asn == dest or bdrmapit.bgp.rel(interface.asn, dest):
            return dest
    return original_min


def annotate(bdrmapit: Bdrmapit, router: Router):
    utype = -1
    rdests = router.dests
    if DEBUG: print('Dests: {}'.format(rdests))
    interface = router.interfaces[0]
    iasn = interface.asn
    if len(rdests) == 0 or all(dest <= 0 for dest in rdests):
        return iasn, NODEST
    rorgs = {bdrmapit.as2org[d] for d in rdests}
    if len(rorgs) == 1:
        dest = list(rdests)[0]
        utype = SINGLE
    else:
        if DEBUG: print('IASN: {}'.format(iasn))
        if iasn in rdests:
            if DEBUG: print('Same: {}'.format(iasn))
            return iasn, 8
        rels: List[int] = [dest for dest in rdests if bdrmapit.bgp.rel(iasn, dest)]
        if DEBUG: print('Rels: {}'.format(rels))
        if rels:
            asn = min(rels, key=lambda x: (bdrmapit.bgp.conesize[x], -x))
            return asn, 9
        dest = heaptest(bdrmapit, rdests, interface)
        if utype == MODIFIED:
            utype = HEAPED_MODIFIED
        else:
            utype = HEAPED
    if iasn > 0 and iasn != dest and not bdrmapit.bgp.rel(iasn, dest):
        if DEBUG: print('No Rel: {}-{}'.format(iasn, dest))
        intersection = bdrmapit.bgp.providers[dest] & bdrmapit.bgp.customers[iasn]
        if len(intersection) == 1:
            dest = peek(intersection)
            return dest, MISSING_INTER
        if DEBUG: print(bdrmapit.bgp.providers[dest] & bdrmapit.bgp.peers[iasn])
        return iasn, MISSING_NOINTER
    return dest, utype


def annotate_lasthops(bdrmapit: Bdrmapit, routers: List[Router]):
    ifs = 0
    ds = 0
    pb = Progress(len(routers), message='Last Hops', increment=100000, callback=lambda: 'Is {:,d} Ds {:,d}'.format(ifs, ds))
    for router in pb.iterator(routers):
        dest, utype = annotate(bdrmapit, router)
        if utype == NODEST:
            ifs += 1
        else:
            ds += 1
        bdrmapit.lhupdates.add_update(router, dest, bdrmapit.as2org[dest], utype)
    bdrmapit.lhupdates.advance()
