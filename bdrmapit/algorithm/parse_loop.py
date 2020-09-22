import pickle
from collections import defaultdict

from bdrmapit.algorithm.parse_results_container import Container


class ContainerLoop(Container):
    def __init__(self, ip2as, as2org, adjs=None, loop=None, **kwargs):
        super().__init__(ip2as, as2org, **kwargs)
        self.adjs = adjs
        self.loop = loop

    def loadloop(self, file):
        with open(file, 'rb') as f:
            loopinfo = pickle.load(f)
        self.adjs = loopinfo['adjs']
        self.loop = loopinfo['loop']

    def remove_loops(self, prunedict, edgedict):
        for x, ys in prunedict.items():
            if x in edgedict:
                newys = [y for y in edgedict[x] if y not in ys]
                if not newys:
                    del edgedict[x]
                else:
                    edgedict[x] = newys

    def prune_loopinfo(self):
        prune = {t for t, n in self.loop.items() if n / self.adjs[t] >= .5}
        prunedict = defaultdict(set)
        for x, y in prune:
            prunedict[x].add(y)
        self.remove_loops(prunedict, self.nexthop)
        self.remove_loops(prunedict, self.multi)

    def prune_addrs(self):
        oldaddrs = set(self.addrs)
        self.addrs = {a for t, n in self.adjs.items() if t not in self.loop or self.loop[t] / n < .5 for a in t if a in oldaddrs}
        for x, ys in self.nexthop.items():
            self.addrs.add(x)
            self.addrs.update(ys)
        for x, ys in self.multi.items():
            self.addrs.add(x)
            self.addrs.update(ys)
