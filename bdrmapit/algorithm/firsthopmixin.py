from collections import defaultdict, Counter
from typing import Optional

from traceutils.as2org.as2org import AS2Org
from traceutils.bgp.bgp import BGP
from traceutils.progress import Progress
from traceutils.utils.utils import peek, max_num

from bdrmapit.algorithm import debug
from bdrmapit.algorithm.updates_dict import Updates
from bdrmapit.graph.construct import Graph
from bdrmapit.graph.node import Interface


class FirstHopMixin:
    as2org: Optional[AS2Org] = None
    bgp: Optional[BGP] = None
    graph: Optional[Graph] = None
    caches: Optional[Updates] = None
    iupdates: Optional[Updates] = None

    def annotate_firsthop(self, interface: Interface, votes):
        if len(votes) == 1:
            asn = peek(votes)
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
            asn = min(rels, key=lambda x: (x != interface.asn, -self.bgp.conesize[x], x))
        return asn

    def annotate_firsthops(self, firstcounters, filemap):
        prevs = defaultdict(Counter)
        pb = Progress(len(firstcounters), 'Creating previous ASNs', increment=100000, callback=lambda: '{:,d}'.format(len(prevs)))
        for file, addr in pb.iterator(firstcounters):
            if file in filemap:
                prevs[addr][filemap[file]] += 1
        pb = Progress(len(prevs), 'Annotating first hops', increment=100000, callback=lambda: '{:,d}'.format(len(prevs)))
        for addr, files in pb.iterator(prevs.items()):
            interface = self.graph.interfaces[addr]
            if addr in prevs and self.iupdates.asn(interface) == -1:
                asn = self.annotate_firsthop(interface, prevs[addr])
                self.caches.add_update_direct(interface, asn, self.as2org[asn], 3)
