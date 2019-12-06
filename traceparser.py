#!/usr/bin/env python
import pickle
from argparse import ArgumentParser
from collections import Counter
from enum import Enum
from multiprocessing.pool import Pool
from typing import Optional

from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS, create_table
from traceutils.scamper.atlas import AtlasReader
from traceutils.scamper.hop import ICMPType
from traceutils.scamper.warts import WartsReader
from traceutils.scamper.pyatlas import AtlasReader as AtlasOddReader

_ip2as: Optional[IP2AS] = None

class OutputType(Enum):
    WARTS = 1
    ATLAS = 2
    ATLAS_ODD = 3

class TraceFile:
    def __init__(self, filename, type):
        self.filename = filename
        self.type = type

    def __repr__(self):
        return self.filename

class ParseResults:

    def __init__(self):
        self.addrs = set()
        # self.adjs = set()
        self.dps = set()
        self.spoofing = set()
        self.echos = set()
        self.cycles = set()
        self.loopadjs = Counter()
        self.nextadjs = Counter()
        self.multiadjs = Counter()

    def __repr__(self):
        return 'Addrs {addrs:,d} N {nhop:,d} M {multi:,d} DPs {dests:,d} S {spoof:,d} E {echo:,d} C {cycle:,d} L {loop:,d}'.format(
            addrs=len(self.addrs), nhop=len(self.nextadjs), multi=len(self.multiadjs), dests=len(self.dps),
            spoof=len(self.spoofing), echo=len(self.echos), cycle=len(self.cycles), loop=len(self.loopadjs)
        )

    def __str__(self):
        return self.__repr__()

    def dump(self, file):
        with open(file, 'wb') as f:
            pickle.dump(vars(self), f)

    @classmethod
    def load(cls, file):
        with open(file, 'rb') as f:
            d = pickle.load(f)
        results = cls()
        for k in d:
            if hasattr(results, k):
                getattr(results, k).update(d[k])
        return results

    def update(self, results):
        self.addrs.update(results.addrs)
        # self.adjs.update(results.adjs)
        self.dps.update(results.dps)
        self.spoofing.update(results.spoofing)
        self.echos.update(results.echos)
        self.cycles.update(results.cycles)
        self.loopadjs.update(results.loopadjs)
        self.nextadjs.update(results.nextadjs)
        self.multiadjs.update(results.multiadjs)

def parse(tfile: TraceFile):
    results: ParseResults = ParseResults()
    addrs = results.addrs
    # adjs = results.adjs
    dps = results.dps
    spoofing = results.spoofing
    echos = results.echos
    cycles = results.cycles
    loopadjs = results.loopadjs
    nextadjs = results.nextadjs
    multiadjs = results.multiadjs
    filename = tfile.filename
    output_type = tfile.type

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
                    if distance == 1:
                        nextadjs[x.addr, y.addr] += 1
                    else:
                        multiadjs[x.addr, y.addr] += 1
            if trace.loop:
                for x, y in zip(trace.loop, trace.loop[1:]):
                    loopadjs[x.addr, y.addr] += 1
    finally:
        f.close()
    return results

def parse_sequential(files, ip2as: IP2AS):
    global _ip2as
    results = ParseResults()
    _ip2as = ip2as

    pb = Progress(len(files), 'Parsing traceroute files', callback=lambda: str(results))
    for tfile in pb.iterator(files):
        newresults = parse(tfile)
        results.update(newresults)
    return results

def parse_parallel(files, ip2as: IP2AS, poolsize):
    global _ip2as
    results = ParseResults()
    _ip2as = ip2as

    pb = Progress(len(files), 'Parsing traceroute files', callback=lambda: str(results))
    with Pool(poolsize) as pool:
        for newresults in pb.iterator(pool.imap_unordered(parse, files)):
            results.update(newresults)
    return results

def run(files, ip2as: IP2AS, poolsize, output=None):
    poolsize = min(len(files), poolsize)
    results = parse_parallel(files, ip2as, poolsize) if poolsize != 1 else parse_sequential(files, ip2as)
    if output:
        results.dump(output)
    return results

def main():
    parser = ArgumentParser()
    parser.add_argument('-w', '--wfiles', help='File with list of newline-separated filenames.')
    parser.add_argument('-W', '--wfilelist', nargs='+', help='List of filenames, space separated.')
    parser.add_argument('-i', '--ip2as', required=True)
    parser.add_argument('-p', '--poolsize', type=int, default=1)
    parser.add_argument('-o', '--output', required=True)
    args = parser.parse_args()
    files = []
    if args.wfiles:
        with File2(args.wfiles) as f:
            files.extend(TraceFile(line.strip(), OutputType.WARTS) for line in f if line[0] != '#')
    if args.wfilelist:
        files.extend(TraceFile(file, OutputType.WARTS) for file in args.wfilelist)
    ip2as = create_table(args.ip2as)
    run(files, ip2as, args.poolsize, args.output)

if __name__ == '__main__':
    main()
