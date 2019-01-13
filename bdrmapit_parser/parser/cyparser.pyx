from collections import defaultdict
from multiprocessing.pool import Pool

from traceutils.progress.bar import Progress
from traceutils.radix.ip2as cimport IP2AS
from traceutils.scamper.atlas cimport AtlasReader
from traceutils.scamper.hop cimport Reader, Trace, Hop
from traceutils.scamper.warts cimport WartsReader


cdef IP2AS _ip2as


cdef class TraceFile:
    def __init__(self, str filename, OutputType type):
        self.filename = filename
        self.type = type

    def __repr__(self):
        return self.filename


# @cython.wraparound(False)
# @cython.boundscheck(False)
cpdef tuple parse(TraceFile tfile):
    cdef set addrs = set()
    cdef set adjs = set()
    cdef set dps = set()
    cdef Reader f
    cdef Trace trace
    cdef list hops
    cdef int dst_asn, i, distance
    cdef Hop x, y
    cdef str filename = tfile.filename
    cdef OutputType output_type = tfile.type

    if output_type == OutputType.WARTS:
        f = WartsReader(filename)
    elif output_type == OutputType.ATLAS:
        f = AtlasReader(filename)
    else:
        raise Exception('Invalid output type: {}.'.format(output_type))
    try:
        f.open()
        for trace in f:
            trace.prune_dups()
            trace.prune_loops()
            # trace.set_packed()
            hops = trace.hops
            dst_asn = _ip2as.asn(trace.dst)
            for i in range(len(hops)):
                x = hops[i]
                addrs.add(x.addr)
                if x.icmp_type != 0:
                    dps.add((x.addr, dst_asn))
                if i == len(hops) - 1:
                    break
                y = hops[i+1]
                if y.icmp_type == 0:
                    break
                distance = y.probe_ttl - x.probe_ttl
                if y.icmp_q_ttl == 0:
                    distance += 1
                if distance > 1:
                    distance = 2
                elif distance < 1:
                    distance = -1
                adjs.add((x.addr, y.addr, distance))
    finally:
        f.close()
    return addrs, adjs, dps


def parse_sequential(list files, IP2AS ip2as):
    global _ip2as
    cdef set addrs = set(), adjs = set(), dps = set()
    cdef TraceFile tfile

    _ip2as = ip2as
    pb = Progress(len(files), 'Parsing traceroute files', callback=lambda: 'Addrs {:,d} Adjs {:,d} DPs {:,d}'.format(len(addrs), len(adjs), len(dps)))
    for tfile in pb.iterator(files):
        # parse(tfile.filename, tfile.type, ip2as, addrs=addrs, adjs=adjs, dps=dps)
        newaddrs, newadjs, newdps = parse(tfile)
        addrs.update(newaddrs)
        adjs.update(newadjs)
        dps.update(newdps)
    return addrs, adjs, dps


def parse_parallel(list files, IP2AS ip2as, poolsize):
    global _ip2as
    cdef set addrs = set(), adjs = set(), dps = set()
    cdef TraceFile tfile
    _ip2as = ip2as

    pb = Progress(len(files), 'Parsing traceroute files', callback=lambda: 'Addrs {:,d} Adjs {:,d} DPs {:,d}'.format(len(addrs), len(adjs), len(dps)))
    with Pool(poolsize) as pool:
        for newaddrs, newadjs, newdps in pb.iterator(pool.imap_unordered(parse, files)):
            addrs.update(newaddrs)
            adjs.update(newadjs)
            dps.update(newdps)
    return addrs, adjs, dps


cdef dict listify(d):
    cdef str k
    cdef set v
    return {k: list(v) for k, v in d.items()}


cpdef dict build_graph_json(set addrs, set adjs, set dps, IP2AS ip2as):
    cdef dict results = {'addrs': list(addrs)}
    cdef set remaining = set()
    cdef str x, y
    cdef int distance
    nexthop = defaultdict(set)
    multi = defaultdict(set)
    for x, y, distance in adjs:
        if distance == 1 or ip2as[x] == ip2as[y]:
            nexthop[x].add(y)
        elif distance > 0:
            remaining.add((x, y))
    for x, y in remaining:
        if x not in nexthop:
            multi[x].add(y)
    results['nexthop'] = listify(nexthop)
    results['multi'] = listify(multi)
    dests = defaultdict(set)
    for addr, asn in dps:
        dests[addr].add(asn)
    results['dps'] = listify(dests)
    return results
