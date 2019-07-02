from collections import Counter, defaultdict
from itertools import combinations
from typing import List, Set, Dict

from traceutils.bgp.bgp import BGP
from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS
from traceutils.utils.utils import max_num, peek
import pandas as pd


class Annotate:

    def __init__(self, ip2as: IP2AS):
        self.nodes: Dict[str, Set[str]] = None
        self.node_ases: Dict[str, Counter] = None
        self.ip2as = ip2as
        self.neighbors = None
        self.degree_matrix = None
        self.annotations = None
        self.method = None

    def read_nodes(self, filename):
        self.nodes = {}
        self.node_ases = {}
        pb = Progress(message='Collecting nodes', increment=1000000, callback=lambda: 'Nodes {:,d}'.format(len(self.nodes)))
        with File2(filename, 'rt') as f:
            for line in pb.iterator(f):
                if not line[0] == '#':
                    _, nid, *ips = line.split()
                    nid = nid[:-1]
                    addrs = []
                    asns = Counter()
                    for addr in ips:
                        asn = self.ip2as[addr]
                        if asn >= 0 or asn <= -100:
                            addrs.append(addr)
                            if asn > 0:
                                asns[asn] += 1
                    if addrs:
                        self.nodes[nid] = addrs
                        self.node_ases[nid] = asns

    def build_neighbors(self):
        self.neighbors = defaultdict(set)
        pb = Progress(len(self.node_ases), 'Finding AS neighbors', increment=500000)
        for asns in pb.iterator(self.node_ases.values()):
            for x, y in combinations(asns, 2):
                self.neighbors[x].add(y)
                self.neighbors[y].add(x)

    def compute_degree_matrix(self):
        self.degree_matrix = {k: len(v) for k, v in self.neighbors.items()}
        self.degree_matrix = Counter(self.degree_matrix)

    def annotate_node(self, nid):
        matrix = self.node_ases[nid]
        if matrix:
            if len(matrix) == 1:
                return peek(matrix), 'single'
            ases = max_num(matrix, key=matrix.__getitem__)
            if len(ases) == 1:
                return ases[0], 'election'
            return min(matrix, key=lambda x: (self.degree_matrix[x], -x)), 'election+degree'
        return 0, 'none'

    def annotate_nodes(self):
        self.annotations = {}
        self.method = {}
        pb = Progress(len(self.nodes), 'Annotating nodes', increment=500000)
        for nid in pb.iterator(self.nodes):
            asn, method = self.annotate_node(nid)
            self.annotations[nid] = asn
            self.method[nid] = method

    def df(self, addrs=None):
        rows = []
        pb = Progress(len(self.nodes), 'Creating DataFrame', increment=1000000, callback=lambda: '{:,d}'.format(len(rows)))
        for nid, node in pb.iterator(self.nodes.items()):
            annotation = self.annotations[nid]
            method = self.method[nid]
            for addr in node:
                if not addrs or addr in addrs:
                    row = [addr, nid, annotation, method]
                    rows.append(row)
        return pd.DataFrame(rows, columns=['addr', 'node', 'asn', 'method'])
