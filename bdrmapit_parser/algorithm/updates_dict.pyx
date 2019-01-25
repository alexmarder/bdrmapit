from bdrmapit_parser.graph.node cimport Node


cdef class UpdateObj:
    def __eq__(self, other):
        if isinstance(other, UpdateObj):
            return self.asn == other.asn
        return False

    def __repr__(self):
        return '<ASN={}, Org={}, UType={}>'.format(self.asn, self.org, self.utype)


cdef class Updates(dict):

    def __init__(self, *args, str name=None, **kargs):
        super().__init__(*args, **kargs)
        self.name = name
        self.changes = {}

    # def __setitem__(self, key, value):
    #     if self[key] != value:
    #         self.changes[key] = value

    def __missing__(self, Node key):
        return None

    cpdef void add_update(self, Node node, int asn, str org, int utype) except *:
        cdef UpdateObj update = UpdateObj()
        update.asn = asn
        update.org = org
        update.utype = utype
        if self[node] != update:
            self.changes[node] = update

    cpdef void add_update_direct(self, Node node, int asn, str org, int utype) except *:
        cdef UpdateObj update = UpdateObj()
        update.asn = asn
        update.org = org
        update.utype = utype
        self[node] = update

    cpdef void advance(self) except *:
        self.update(self.changes)
        self.changes = {}

    cpdef int asn(self, node) except *:
        cdef UpdateObj value = self[node]
        if value is not None:
            return value.asn
        return -1

    cpdef Updates make_copy(self, str name=None):
        if name is None:
            name = self.name
        return Updates(self, name=name)

    cpdef str org(self, Node node):
        cdef UpdateObj value = self[node]
        return value.org


cdef class UpdatesView(Updates):

    def __init__(self, original: Updates, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.original = original

    def __missing__(self, key):
        return self.original[key]
