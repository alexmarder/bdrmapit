#!/usr/bin/env python
import pickle
from argparse import ArgumentParser
from collections import Counter, defaultdict
from enum import Enum
from multiprocessing.pool import Pool
from typing import Optional, List, Dict

from traceutils.file2.file2 import File2, fopen
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS, create_table, create_private
from traceutils.scamper.atlas import AtlasReader
from traceutils.scamper.hop import ICMPType, Hop
from traceutils.scamper.warts import WartsReader, WartsJsonReader
from traceutils.scamper.pyatlas import AtlasReader as AtlasOddReader
from traceutils.utils.net import otherside, prefix_addrs

print('test')

_ip2as: Optional[IP2AS] = None
_filemap4: Optional[Dict[str, str]] = None
_filemap6: Optional[Dict[str, str]] = None
_prune_loops = False
_noechos = False
_subnet = False
_include_dsts = False
_fours = False

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
    addrs = set()
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
        fiter = iter(f)
        while True:
            try:
                trace = next(fiter)
            except StopIteration:
                break
            except (OSError, UnicodeDecodeError, EOFError):
                print(tfile.filename)
                break
            if _include_dsts:
                addrs.add(trace.dst)
            trace.prune_private(_ip2as)
            trace.prune_dups()
            if _prune_loops:
                trace.prune_loops(True)
            if _fours:
                for hop in trace.hops:
                    if hop.type != ICMPType.echo_reply:
                        addr = hop.addr
                        addrs.update(prefix_addrs(addr, 2))
            else:
                addrs.update(hop.addr for hop in trace.hops if not (_noechos and hop.type == ICMPType.echo_reply))
                if _subnet:
                    for hop in trace.hops:
                        if not (_noechos and hop.type == ICMPType.echo_reply):
                            addr = hop.addr
                            try:
                                other4 = otherside(addr, 4)
                                addrs.add(other4)
                            except:
                                pass
                            other2 = otherside(addr, 2)
                            addrs.add(other2)
    finally:
        f.close()
    return addrs

# def parse(tfile: TraceFile):
#     addrs = set()
#     if tfile.type == OutputType.WARTS:
#         f = WartsReader(tfile.filename, ping=False)
#     elif tfile.type == OutputType.ATLAS:
#         f = AtlasReader(tfile.filename)
#     elif tfile.type == OutputType.ATLAS_ODD:
#         f = AtlasOddReader(tfile.filename)
#     elif tfile.type == OutputType.JSONWARTS:
#         f = WartsJsonReader(tfile.filename)
#     else:
#         raise Exception('Invalid output type: {}.'.format(tfile.type))
#     try:
#         f.open()
#         for trace in f:
#             if _include_dsts:
#                 addrs.add(trace.dst)
#             trace.prune_private(_ip2as)
#             trace.prune_dups()
#             if _prune_loops:
#                 trace.prune_loops(True)
#             if _fours:
#                 print('here')
#                 for hop in trace.hops:
#                     if hop.type != ICMPType.echo_reply:
#                         addr = hop.addr
#                         addrs.update(prefix_addrs(addr, 2))
#             else:
#                 addrs.update(hop.addr for hop in trace.hops if not (_noechos and hop.type == ICMPType.echo_reply))
#                 if _subnet:
#                     for hop in trace.hops:
#                         if not (_noechos and hop.type == ICMPType.echo_reply):
#                             addr = hop.addr
#                             try:
#                                 other4 = otherside(addr, 4)
#                                 addrs.add(other4)
#                             except:
#                                 pass
#                             other2 = otherside(addr, 2)
#                             addrs.add(other2)
#
#     except (OSError, UnicodeDecodeError):
#         print(tfile.filename)
#         raise
#     except (EOFError):
#         print(tfile.filename)
#     finally:
#         f.close()
#     return addrs

def parse_sequential(files):
    results = set()
    pb = Progress(len(files), 'Parsing traceroute files', callback=lambda: '{:,d}'.format(len(results)))
    for tfile in pb.iterator(files):
        results.update(parse(tfile))
    return results

def parse_parallel(files, poolsize):
    results = set()
    pb = Progress(len(files), 'Parsing traceroute files', callback=lambda: '{:,d}'.format(len(results)))
    with Pool(poolsize) as pool:
        for newresults in pb.iterator(pool.imap_unordered(parse, files)):
            results.update(newresults)
    return results

def run(files, ip2as: IP2AS, poolsize, output=None, prune_loops=False, noechos=False, subnet=False, include_dsts=False, fours=False):
    global _ip2as, _prune_loops, _noechos, _subnet, _include_dsts, _fours
    _ip2as = ip2as
    _prune_loops = prune_loops
    _noechos = noechos
    _subnet = subnet
    _include_dsts = include_dsts
    _fours = fours

    poolsize = min(len(files), poolsize)
    print(poolsize)
    results = parse_parallel(files, poolsize) if poolsize != 1 else parse_sequential(files)
    if output:
        with fopen(output, 'wt') as f:
            f.writelines(a + '\n' for a in results)
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
    parser.add_argument('-l', '--prune-loops', action='store_true')
    parser.add_argument('-e', '--noechos', action='store_true')
    parser.add_argument('-d', '--include-dsts', action='store_true')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-s', '--subnet', action='store_true')
    group.add_argument('-4', '--fours', action='store_true')
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
    run(files, ip2as, args.poolsize, args.output, prune_loops=args.prune_loops, noechos=args.noechos, subnet=args.subnet, include_dsts=args.include_dsts, fours=args.fours)

if __name__ == '__main__':
    main()
