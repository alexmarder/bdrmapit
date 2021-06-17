cdef class Router:
    cdef:
        readonly str name
        readonly list interfaces
        public bint nexthop
        public bint vrf
        readonly set succ
        readonly set dests
        readonly dict origins
        public bint echo
        public bint cycle
        public set hints

    cpdef Router copy(self);

cdef class Interface:
    cdef:
        readonly str addr
        readonly int asn
        readonly str org
        public Router router
        readonly dict pred
        public set dests
        public bint vrf
        public bint echo
        public bint cycle
        public int hint

    cpdef Interface copy(self);

ctypedef fused Node:
    Router
    Interface