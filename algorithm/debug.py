from abc import ABC, abstractmethod
from typing import Optional

from bdrmapit_parser.algorithm.updates_dict import Updates
from bdrmapit_parser.graph.construct import Graph
from bdrmapit_parser.graph.node import Router, Interface

DEBUG = False

class Debug:

    def __init__(self, bdrmapit=None, rupdates=None, iupdates=None, verbose=True):
        self.old = DEBUG
        self.bdrmapit = bdrmapit
        self.rupdates = rupdates
        self.iupdates = iupdates
        self.old_rupdates = None
        self.old_iupdates = None
        self.verbose = verbose

    def __enter__(self):
        global DEBUG
        DEBUG = self.verbose
        if self.bdrmapit is not None:
            if self.rupdates is not None:
                self.old_rupdates, self.bdrmapit.rupdates = self.bdrmapit.rupdates, self.rupdates
            if self.iupdates is not None:
                self.old_iupdates, self.bdrmapit.iupdates = self.bdrmapit.iupdates, self.iupdates

    def __exit__(self, exc_type, exc_val, exc_tb):
        global DEBUG
        DEBUG = self.old
        if self.bdrmapit is not None:
            if self.rupdates is not None:
                self.bdrmapit.rupdates = self.old_rupdates
            if self.iupdates is not None:
                self.bdrmapit.iupdates = self.old_iupdates
        return False

class DebugMixin(ABC):

    def __init__(self):
        self.graph: Optional[Graph] = None

    @abstractmethod
    def annotate_lasthop(self, router: Router):
        raise NotImplementedError()

    @abstractmethod
    def annotate_router(self, router: Router):
        raise NotImplementedError()

    @abstractmethod
    def annotate_router_vrf(self, router: Router):
        raise NotImplementedError()

    @abstractmethod
    def annotate_interface(self, interface: Interface):
        raise NotImplementedError()

    def test_last(self, nid, rupdates=None, iupdates=None):
        if rupdates is None:
            rupdates = Updates()
        if iupdates is None:
            iupdates = Updates()
        with Debug(self, rupdates=rupdates, iupdates=iupdates):
            if not isinstance(nid, Router):
                r: Router = self.graph.routers[nid]
            else:
                r = nid
            result = self.annotate_lasthop(r)
        print(result)

    def test_router(self, nid, rupdates=None, iupdates=None):
        with Debug(self, rupdates=rupdates, iupdates=iupdates):
            try:
                r: Router = self.graph.routers[nid]
            except KeyError:
                r: Router = self.graph.interfaces[nid].router
            if r.vrf:
                result = self.annotate_router_vrf(r)
            else:
                result = self.annotate_router(r)
        print(result)

    def test_interface(self, addr, rupdates=None, iupdates=None):
        with Debug(self, rupdates=rupdates, iupdates=iupdates):
            i = self.graph.interfaces[addr]
            result = self.annotate_interface(i)
        print(result)
