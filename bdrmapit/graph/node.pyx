# from collections import defaultdict

cdef class Router:

    def __init__(self, str name):
        self.name = name
        self.interfaces = []
        self.nexthop = False
        self.vrf = False
        self.succ = set()
        self.dests = set()
        self.origins = {}
        # self.origins = defaultdict(set)
        self.hints = None

    def __repr__(self):
        return 'Router<{}>'.format(self.name)

    cpdef Router copy(self):
        router = Router(self.name)
        router.interfaces.extend(self.interfaces)
        router.nexthop = self.nexthop
        router.vrf = self.vrf
        router.succ.update(self.succ)
        router.dests.update(self.dests)
        router.origins.update(self.origins)
        router.hints = self.hints
        return router

cdef class Interface:

    def __init__(self, str addr, int asn, str org):
        self.addr = addr
        self.asn = asn
        self.org = org
        self.router = None
        self.pred = {}
        self.dests = set()
        self.vrf = False
        # self.mpls = False
        self.hint = 0

    def __repr__(self):
        return 'Interface<{} {}>'.format(self.addr, self.asn)

    cpdef Interface copy(self):
        iface = Interface(self.addr, self.asn, self.org)
        iface.router = self.router
        iface.pred.update(self.pred)
        iface.dests.update(self.dests)
        iface.vrf = self.vrf
        iface.hint = self.hint
        return iface
