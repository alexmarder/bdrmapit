from traceutils.progress.bar import Progress
from traceutils.radix.ip2as cimport IP2AS
from traceutils.scamper.atlas cimport AtlasReader
from traceutils.scamper.hop cimport Reader, Trace, Hop
from traceutils.scamper.warts cimport WartsReader


cdef class TraceFile:
    def __init__(self, str filename, OutputType type):
        self.filename = filename
        self.type = type

    def __repr__(self):
        return self.filename


# @cython.wraparound(False)
# @cython.boundscheck(False)
cpdef tuple parse(str filename, OutputType output_type, IP2AS ip2as, set addrs=None, set adjs=None, set dps=None):
    # cdef set addrs = set()
    # cdef set adjs = set()
    # cdef set dps = set()
    cdef Reader f
    cdef Trace trace
    cdef list hops
    cdef int dst_asn, i, distance
    cdef Hop x, y
    cdef bint should_return = addrs is None or adjs is None or dps is None

    if addrs is None:
        addrs = set()
    if adjs is None:
        adjs = set()
    if dps is None:
        dps = set()

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
            addrs.update(trace.addrs())
            hops = trace.hops
            dst_asn = ip2as.asn(trace.dst)
            for i in range(len(hops)):
                x = hops[i]
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
    if should_return:
        return addrs, adjs, dps


def parse_sequential(list files, IP2AS ip2as):
    cdef set addrs = set(), adjs = set(), dps = set()
    cdef TraceFile tfile

    pb = Progress(len(files), 'Parsing traceroute files', callback=lambda: 'Addrs {:,d} Adjs {:,d} DPs {:,d}'.format(len(addrs), len(adjs), len(dps)))
    for tfile in pb.iterator(files):
        # parse(tfile.filename, tfile.type, ip2as, addrs=addrs, adjs=adjs, dps=dps)
        newaddrs, newadjs, newdps = parse(tfile.filename, tfile.type, ip2as)
        addrs.update(newaddrs)
        adjs.update(newadjs)
        dps.update(newdps)
    return addrs, adjs, dps
