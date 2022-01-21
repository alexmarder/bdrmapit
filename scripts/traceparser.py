#!/usr/bin/env python
import pickle
from argparse import ArgumentParser
from collections import Counter, defaultdict
from enum import Enum
from multiprocessing.pool import Pool
from typing import Optional, List, Dict

from traceutils.file2.file2 import File2, fopen
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS, create_table
from traceutils.scamper.atlas import AtlasReader
from traceutils.scamper.hop import ICMPType, Hop
from traceutils.scamper.warts import WartsReader, WartsJsonReader
# from traceutils.scamper.pyatlas import AtlasReader as AtlasOddReader

_ip2as: Optional[IP2AS] = None
_filemap4: Optional[Dict[str, str]] = None
_filemap6: Optional[Dict[str, str]] = None

class OutputType(Enum):
    WARTS = 1
    ATLAS = 2
    ATLAS_ODD = 3
    JSONWARTS = 4

class TraceFile:
    def __init__(self, filename, type):
        self.filename = filename
        self.type = type

    def __repr__(self):
        return self.filename

class ParseResults:

    def __init__(self):
        self.addrs = set()
        self.dps = set()
        self.spoofing = set()
        self.echos = set()
        self.cycles = set()
        self.loopadjs = Counter()
        self.nextadjs = Counter()
        self.multiadjs = Counter()
        self.first = Counter()
        # self.triplets = Counter()

    def __repr__(self):
        return 'Addrs {addrs:,d} N {nhop:,d} M {multi:,d} DPs {dests:,d} S {spoof:,d} E {echo:,d} C {cycle:,d} L {loop:,d} F {first:,d}'.format(
            addrs=len(self.addrs), nhop=len(self.nextadjs), multi=len(self.multiadjs), dests=len(self.dps),
            spoof=len(self.spoofing), echo=len(self.echos), cycle=len(self.cycles), loop=len(self.loopadjs),
            first=len(self.first),
            # triplets=len(self.triplets)
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
        for k, v in vars(results).items():
            getattr(self, k).update(v)

def parse(tfile: TraceFile):
    # public_ip4 = _filemap4.get(tfile.filename)
    # public_ip6 = _filemap6.get(tfile.filename)
    results: ParseResults = ParseResults()
    if tfile.type == OutputType.WARTS:
        f = WartsReader(tfile.filename, ping=False)
    elif tfile.type == OutputType.ATLAS:
        f = AtlasReader(tfile.filename)
    elif tfile.type == OutputType.ATLAS_ODD:
        f = AtlasOddReader(tfile.filename)
    elif tfile.type == OutputType.JSONWARTS:
        f = WartsJsonReader(tfile.filename)
    else:
        raise Exception('Invalid output type: {}.'.format(tfile.type))
    f.open()
    if f.addr:
        public_ip4 = f.addr
        public_ip6 = f.addr
    else:
        public_ip4 = _filemap4[f.hostname] if f.hostname in _filemap4 else _filemap4.get(tfile.filename)
        public_ip6 = _filemap6[f.hostname] if f.hostname in _filemap6 else _filemap6.get(tfile.filename)
    try:
        fiter = iter(f)
        while True:
            try:
                trace = next(fiter)
                trace.prune_private(_ip2as)
                trace.prune_dups()
                trace.prune_loops(True)
                if trace.loop:
                    results.cycles.update(trace.loop)
                hops: List[Hop] = [h for h in trace.hops if _ip2as[h.addr] != -1 and h.addr != trace.src and h.addr != public_ip4 and h.addr != public_ip6]
                if not hops: continue
                fhop: Hop = hops[0]
                if fhop.probe_ttl == 1:
                    results.first[tfile.filename, fhop.addr] += 1
                lhop: Hop = hops[-1]
                if lhop.type == ICMPType.echo_reply or lhop.type == ICMPType.portping:
                    results.echos.add(lhop.addr)
                dst_asn = _ip2as.asn(trace.dst)
                for i in range(len(hops)):
                    x: Hop = hops[i]
                    results.addrs.add(x.addr)
                    if x.type != ICMPType.echo_reply and x.type != ICMPType.portping:
                        results.dps.add((x.addr, dst_asn))
                    if i == len(hops) - 1:
                        break
                    y: Hop = hops[i+1]
                    if y.type == ICMPType.echo_reply or y.type == ICMPType.portping:
                        break
                    if y.type == ICMPType.spoofing and y.icmp_q_ttl > 1:
                        break
                    distance = y.probe_ttl - x.probe_ttl
                    if y.icmp_q_ttl == 0:
                        distance += 1
                    if distance > 1:
                        distance = 2
                    elif distance < 1:
                        distance = -1
                    if y.type == ICMPType.spoofing:
                        results.spoofing.add((x.addr, y.addr, distance))
                    else:
                        if distance == 1:
                            results.nextadjs[x.addr, y.addr] += 1
                        else:
                            results.multiadjs[x.addr, y.addr] += 1
                if trace.loop:
                    for x, y in zip(trace.loop, trace.loop[1:]):
                        results.loopadjs[x.addr, y.addr] += 1
            except UnicodeDecodeError:
                print(tfile.filename, 'UnicodeDecodeError')
                break
            except EOFError:
                print(tfile.filename, 'EOFError')
                break
            except StopIteration:
                break
    finally:
        f.close()
    return results

def parse_sequential(files):
    results = ParseResults()

    pb = Progress(len(files), 'Parsing traceroute files', callback=lambda: str(results))
    for tfile in pb.iterator(files):
        newresults = parse(tfile)
        results.update(newresults)
    return results

def parse_parallel(files, poolsize):
    results = ParseResults()

    pb = Progress(len(files), 'Parsing traceroute files', callback=lambda: str(results))
    with Pool(poolsize) as pool:
        for newresults in pb.iterator(pool.imap_unordered(parse, files)):
            results.update(newresults)
    return results

def run(files, ip2as: IP2AS, poolsize, output=None, filemap4=None, filemap6=None):
    global _ip2as, _filemap4, _filemap6
    _ip2as = ip2as
    _filemap4 = filemap4 if filemap4 is not None else {}
    _filemap6 = filemap6 if filemap6 is not None else {}

    poolsize = min(len(files), poolsize)
    print(poolsize)
    results = parse_parallel(files, poolsize) if poolsize != 1 else parse_sequential(files)
    if output:
        results.dump(output)
    return results

def read_filemap(filename):
    filemap = {}
    with open(filename) as f:
        for line in f:
            if line[0] == '#':
                continue
            file, addr = line.split()
            filemap[file] = addr
    return filemap

def set_parser(parser: ArgumentParser, group=None, output=True):
    oparser = parser
    if group is not None:
        parser = parser.add_argument_group(group)
    parser.add_argument('-w', '--wfiles', help='File with list of newline-separated warts filenames.')
    parser.add_argument('-W', '--wfilelist', nargs='+', help='List of warts filenames, space separated.')
    parser.add_argument('-a', '--afiles', help='File with list of newline-separated atlas filenames.')
    parser.add_argument('-A', '--afilelist', nargs='+', help='List of filenames, space separated.')
    parser.add_argument('-j', '--jfiles')
    parser.add_argument('-J', '--jfilelist', nargs='+')
    oparser.add_argument('-i', '--ip2as', required=True, help='Filename of prefix-to-AS mappings in CAIDA prefix2as format.')
    parser.add_argument('-p', '--poolsize', type=int, default=1)
    parser.add_argument('-m', '--filemap4', help='Mapping from filename to public IPv4 address (tab separated).')
    parser.add_argument('-M', '--filemap6', help='Mapping from filename to public IPv4 address (tab separated).')
    if output:
        parser.add_argument('-o', '--output', required=True, help='Filename for pickle output file.')

def main(args=None, ip2as=None):
    if args is None:
        parser = ArgumentParser()
        set_parser(parser)
        args = parser.parse_args()
    files = []
    if args.wfiles:
        with fopen(args.wfiles) as f:
            files.extend(TraceFile(line.strip(), OutputType.WARTS) for line in f if line[0] != '#')
    if args.wfilelist:
        files.extend(TraceFile(file, OutputType.WARTS) for file in args.wfilelist)
    if args.afiles:
        with fopen(args.afiles) as f:
            files.extend(TraceFile(line.strip(), OutputType.ATLAS) for line in f if line[0] != '#')
    if args.afilelist:
        files.extend(TraceFile(file, OutputType.ATLAS) for file in args.afilelist)
    if args.jfiles:
        with fopen(args.jfiles) as f:
            files.extend(TraceFile(line.strip(), OutputType.JSONWARTS) for line in f if line[0] != '#')
    if args.jfilelist:
        files.extend(TraceFile(file, OutputType.JSONWARTS) for file in args.jfilelist)
    filemap4 = read_filemap(args.filemap4) if args.filemap4 else {}
    filemap6 = read_filemap(args.filemap6) if args.filemap6 else {}
    if ip2as is None:
        ip2as = create_table(args.ip2as)
    return run(files, ip2as, args.poolsize, args.output, filemap4=filemap4, filemap6=filemap6)

if __name__ == '__main__':
    main()
