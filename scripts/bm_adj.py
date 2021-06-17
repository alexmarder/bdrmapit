#!/usr/bin/env python
import pickle
from argparse import ArgumentParser
from collections import Counter, defaultdict
from enum import Enum
from multiprocessing.pool import Pool
from typing import Optional, List, Dict

from file2 import fopen
from pb_amarder.bar import Progress
from traceutils.radix.ip2as import IP2AS, create_table, create_private
from traceutils.scamper.atlas import AtlasReader
from traceutils.scamper.hop import ICMPType, Hop
from traceutils.scamper.warts import WartsReader, WartsJsonReader
from traceutils.scamper.pyatlas import AtlasReader as AtlasOddReader

print('current')

_ip2as: Optional[IP2AS] = None
_filemap4: Optional[Dict[str, str]] = None
_filemap6: Optional[Dict[str, str]] = None
_prune_private = True

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

def parse(tfile: TraceFile):
    results = set()
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
    try:
        f.open()
        for trace in f:
            if _prune_private:
                trace.prune_private(_ip2as)
            trace.prune_dups()
            trace.prune_loops(True)
            # if trace.loop:
            #     results.cycles.update(trace.loop)
            hops: List[Hop] = [h for h in trace.hops if _ip2as[h.addr] != -1 and h.addr != trace.src]
            if not hops: continue
            fhop: Hop = hops[0]
            lhop: Hop = hops[-1]
            for i in range(len(hops)):
                x: Hop = hops[i]
                if i == len(hops) - 1:
                    break
                y: Hop = hops[i+1]
                # if y.type == ICMPType.echo_reply or y.type == ICMPType.portping:
                #     break
                if y.type == ICMPType.spoofing and y.icmp_q_ttl > 1:
                    break
                distance = y.probe_ttl - x.probe_ttl
                if y.icmp_q_ttl == 0:
                    distance += 1
                if distance == 1:
                    results.add((x.addr, y.addr, y.icmp_type))
    except UnicodeDecodeError:
        print(tfile.filename)
        raise
    except EOFError:
        print(tfile.filename)
    finally:
        f.close()
    return results

def parse_sequential(files):
    results = set()
    pb = Progress(len(files), 'Parsing traceroute files', callback=lambda: '{:,d}'.format(len(results)))
    for tfile in pb.iterator(files):
        newresults = parse(tfile)
        results.update(newresults)
    return results

def parse_parallel(files, poolsize):
    results = set()
    pb = Progress(len(files), 'Parsing traceroute files', callback=lambda: '{:,d}'.format(len(results)))
    with Pool(poolsize) as pool:
        for newresults in pb.iterator(pool.imap_unordered(parse, files)):
            results.update(newresults)
    return results

def run(files, ip2as: IP2AS, poolsize, output=None, prune_private=True, serialize=False):
    global _ip2as, _filemap4, _filemap6, _prune_private
    _ip2as = ip2as
    _prune_private = prune_private

    poolsize = min(len(files), poolsize)
    print(poolsize)
    results = parse_parallel(files, poolsize) if poolsize != 1 else parse_sequential(files)
    te = set()
    echo = set()
    for x, y, itype in results:
        if itype == 0:
            echo.add((x, y))
        else:
            te.add((x, y))
    echo -= te
    adjs = {(x, y, True) for x, y in te} | {(x, y, False) for x, y in echo}
    if output:
        if serialize:
            with open(output, 'wb') as f:
                pickle.dump(adjs, f)
        else:
            with fopen(output, 'wt') as f:
                for x, y, z in adjs:
                    f.write('{}\t{}\t{}\n'.format(x, y, int(z)))
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

def main():
    parser = ArgumentParser()
    parser.add_argument('-w', '--wfiles', help='File with list of newline-separated filenames.')
    parser.add_argument('-W', '--wfilelist', nargs='+', help='List of filenames, space separated.')
    parser.add_argument('-a', '--afiles', help='File with list of newline-separated filenames.')
    parser.add_argument('-A', '--afilelist', nargs='+', help='List of filenames, space separated.')
    parser.add_argument('-j', '--jfiles')
    parser.add_argument('-J', '--jfilelist', nargs='+')
    parser.add_argument('-p', '--poolsize', type=int, default=1)
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('-k', '--keep-private', action='store_true')
    parser.add_argument('-P', '--pickle', action='store_true')
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
    ip2as = create_private()
    prune_private = not args.keep_private
    run(files, ip2as, args.poolsize, args.output, prune_private=prune_private, serialize=args.pickle)

if __name__ == '__main__':
    main()
