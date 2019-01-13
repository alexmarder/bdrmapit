from collections import defaultdict
from enum import Enum
from typing import Set, Tuple, Dict, Any, List

from traceutils.radix.ip2as import IP2AS
from traceutils.scamper.atlas import AtlasReader
from traceutils.scamper.warts import WartsReader


class OutputType(Enum):
    WARTS = 1
    ATLAS = 2


def parse(filename, output_type: OutputType, ip2as: IP2AS):
    addrs = set()
    adjs = set()
    dps = set()
    # dists = set()
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
            dst_asn = ip2as[trace.dst]
            dps.update((hop.addr, dst_asn) for hop in hops if hop.icmp_type != 0)
            for i in range(len(hops) - 1):
                x = hops[i]
                # if x.icmp_type != 0:
                #     dps.add((x.addr, dst_asn))
                # if i == len(hops) - 1:
                #     break
                y = hops[i+1]
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


def listify(d: Dict[Any, Set[Any]]) -> Dict[Any, List[Any]]:
    return {k: list(v) for k, v in d.items()}


def build_graph(addrs: Set[str], adjs: Set[Tuple[str, str, int]], dps: Set[Tuple[str, int]], ip2as: IP2AS):
    results = {'addrs': addrs}
    remaining = set()
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
    results['nexthop'] = dict(nexthop)
    results['multi'] = dict(multi)
    dests = defaultdict(set)
    for addr, asn in dps:
        dests[addr].add(asn)
    results['dps'] = dict(dests)
    return results


def build_graph_json(addrs: Set[str], adjs: Set[Tuple[str, str, int]], dps: Set[Tuple[str, int]], ip2as: IP2AS):
    # results = {'addrs': addrs}
    results = {'addrs': list(addrs)}
    remaining = set()
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
    # results['nexthop'] = nexthop
    # results['multi'] = multi
    results['nexthop'] = listify(nexthop)
    results['multi'] = listify(multi)
    dests = defaultdict(set)
    for addr, asn in dps:
        dests[addr].add(asn)
    # results['dps'] = dests
    results['dps'] = listify(dests)
    return results
