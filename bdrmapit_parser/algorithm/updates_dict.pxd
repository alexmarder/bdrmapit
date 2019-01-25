from bdrmapit_parser.graph.node cimport Node

cdef class UpdateObj:
    cdef public int asn, utype
    cdef public str org

cdef class Updates(dict):
    cdef public str name
    cdef public dict changes

    cpdef void add_update(self, Node node, int asn, str org, int utype) except *;
    cpdef void add_update_direct(self, Node node, int asn, str org, int utype) except *;
    cpdef void advance(self) except *;
    cpdef int asn(self, node) except *;
    cpdef Updates make_copy(self, str name=*);
    cpdef str org(self, Node node);

cdef class UpdatesView(Updates):
    pass
    