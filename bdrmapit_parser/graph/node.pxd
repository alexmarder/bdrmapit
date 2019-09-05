cdef class Router:
    cdef readonly str name
    cdef readonly list interfaces
    cdef public bint nexthop
    cdef public bint vrf
    cdef readonly set succ
    cdef readonly set dests
    cdef readonly dict origins
    cdef public bint echo
    cdef public bint cycle

cdef class Interface:
    cdef readonly str addr
    cdef readonly int asn
    cdef readonly str org
    cdef public Router router
    cdef readonly dict pred
    cdef public set dests
    cdef public bint vrf
    cdef public bint echo
    cdef public bint cycle

ctypedef fused Node:
    Router
    Interface