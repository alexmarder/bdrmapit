# from collections import defaultdict

cdef class Router:

    def __init__(self, str name):
        self.name = name
        self.interfaces = []
        self.nexthop = False
        self.succ = set()
        self.dests = set()
        self.origins = {}
        # self.origins = defaultdict(set)

    def __repr__(self):
        return 'Router<{}>'.format(self.name)


cdef class Interface:

    def __init__(self, str addr, int asn, str org):
        self.addr = addr
        self.asn = asn
        self.org = org
        self.router = None
        self.pred = {}
        self.dests = set()

    def __repr__(self):
        return 'Interface<{} {}>'.format(self.addr, self.asn)
