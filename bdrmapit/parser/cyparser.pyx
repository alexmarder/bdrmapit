from collections import defaultdict
from multiprocessing.pool import Pool

from traceutils.progress.bar import Progress
from traceutils.radix.ip2as cimport IP2AS
from traceutils.scamper.atlas cimport AtlasReader
from traceutils.scamper.hop import ICMPType
from traceutils.scamper.hop cimport Reader, Trace, Hop
from traceutils.scamper.warts cimport WartsReader
from traceutils.scamper.pyatlas import AtlasReader as AtlasOddReader


cdef IP2AS _ip2as


cdef class TraceFile:
    def __init__(self, str filename, OutputType type):
        self.filename = filename
        self.type = type

    def __repr__(self):
        return self.filename


cdef class ParseResults:

    def __init__(self):
        self.addrs = set()
        self.adjs = set()
        self.dps = set()
        self.mpls = set()
        self.spoofing = set()
        self.echos = set()
        self.cycles = set()
        self.loopadjs = set()

    def __str__(self):
        return 'Addrs {:,d} Adjs {:,d} DPs {:,d} MPLS {:,d} S {:,d} E {:,d} C {:,d}'.format(len(self.addrs), len(self.adjs), len(self.dps), len(self.mpls), len(self.spoofing), len(self.echos), len(self.cycles))

    cpdef void update(self, ParseResults results) except *:
        self.addrs.update(results.addrs)
        self.adjs.update(results.adjs)
        self.dps.update(results.dps)
        self.mpls.update(results.mpls)
        self.spoofing.update(results.spoofing)
        self.echos.update(results.echos)
        self.cycles.update(results.cycles)


cpdef ParseResults parse(TraceFile tfile):
    cdef ParseResults results = ParseResults()
    cdef set addrs = results.addrs
    cdef set adjs = results.adjs
    cdef set dps = results.dps
    cdef set mpls = results.mpls
    cdef set spoofing = results.spoofing
    cdef set echos = results.echos
    cdef set cycles = results.cycles
    cdef Reader f
    cdef Trace trace
    cdef list hops
    cdef int dst_asn, i, distance
    cdef Hop x, y
    cdef str filename = tfile.filename
    cdef OutputType output_type = tfile.type

    if output_type == OutputType.WARTS:
        f = WartsReader(filename, ping=False)
    elif output_type == OutputType.ATLAS:
        f = AtlasReader(filename)
    elif output_type == OutputType.ATLAS_ODD:
        f = AtlasOddReader(filename)
    else:
        raise Exception('Invalid output type: {}.'.format(output_type))
    try:
        f.open()
        for trace in f:
            trace.prune_dups()
            trace.prune_loops()
            if trace.loop:
                cycles.update(trace.loop)
            hops = [h for h in trace.hops if _ip2as[h.addr] != -1]
            dst_asn = _ip2as.asn(trace.dst)
            for i in range(len(hops)):
                x = hops[i]
                addrs.add(x.addr)
                if x.ismpls or (x.icmp_q_ttl > 1 and x.type == ICMPType.time_exceeded):
                    mpls.add(x.addr)
                if x.icmp_type != 0:
                    dps.add((x.addr, dst_asn))
                if i == len(hops) - 1:
                    break
                y = hops[i+1]
                if y.type == ICMPType.echo_reply or y.type == ICMPType.portping:
                    echos.add(y.addr)
                    break
                distance = y.probe_ttl - x.probe_ttl
                if y.icmp_q_ttl == 0:
                    distance += 1
                if distance > 1:
                    distance = 2
                elif distance < 1:
                    distance = -1
                if y.type == ICMPType.spoofing:
                    spoofing.add((x.addr, y.addr, distance))
                else:
                    adjs.add((x.addr, y.addr, distance))
    finally:
        f.close()
    return results


def parse_sequential(list files, IP2AS ip2as):
    global _ip2as
    cdef ParseResults results = ParseResults(), newresults
    cdef TraceFile tfile
    _ip2as = ip2as

    pb = Progress(len(files), 'Parsing traceroute files', callback=lambda: str(results))
    for tfile in pb.iterator(files):
        newresults = parse(tfile)
        results.update(newresults)
    return results


def parse_parallel(list files, IP2AS ip2as, poolsize):
    global _ip2as
    cdef ParseResults results = ParseResults(), newresults
    cdef TraceFile tfile
    _ip2as = ip2as

    pb = Progress(len(files), 'Parsing traceroute files', callback=lambda: str(results))
    with Pool(poolsize) as pool:
        for newresults in pb.iterator(pool.imap_unordered(parse, files)):
            results.update(newresults)
    return results


cdef dict listify(d):
    cdef str k
    cdef set v
    return {k: list(v) for k, v in d.items()}


cpdef dict build_graph_json(ParseResults parseres, IP2AS ip2as):
    cdef dict results = {'addrs': list(parseres.addrs), 'mpls': list(parseres.mpls)}
    cdef set remaining = set()
    cdef str x, y
    cdef int distance

    nexthop = defaultdict(set)
    multi = defaultdict(set)
    for x, y, distance in parseres.adjs:
        if distance == 1 or ip2as[x] == ip2as[y]:
            nexthop[x].add(y)
        elif distance > 0:
            remaining.add((x, y))
    for x, y in remaining:
        if x not in nexthop:
            multi[x].add(y)
    results['nexthop'] = listify(nexthop)
    results['multi'] = listify(multi)
    results['spoofing'] = list(parseres.spoofing)
    dests = defaultdict(set)
    for addr, asn in parseres.dps:
        dests[addr].add(asn)
    results['dps'] = listify(dests)
    results['echos'] = list(parseres.echos)
    results['cycles'] = list(parseres.cycles)
    return results
