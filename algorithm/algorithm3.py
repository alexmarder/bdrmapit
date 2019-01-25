import sys
from collections import Counter, defaultdict
from typing import Collection, List, Set, Dict, DefaultDict, Union, Tuple, Counter as TCounter

from traceutils.progress.bar import Progress
from traceutils.utils.utils import max_num, peek

from bdrmapit_parser.algorithm.bdrmapit import Bdrmapit
from bdrmapit_parser.algorithm.updates_dict import Updates, UpdatesView
from bdrmapit_parser.graph.node import Router, Interface


DEBUG = False

REALLOCATED_PREFIX = 500
REALLOCATED_DEST = 1000
SINGLE_SUCC_ORIGIN = 10
SINGLE_SUCC_4 = 11
SUCC_ORIGIN_INTER = 12
SUCC_ORIGIN_CUST = 13
REMAINING_4 = 14
IUPDATE = 15
ALLPEER_SUCC = 16
ALLPEER_ORIGIN = 17
IASN_SUCC_HALF = 18
ALLRELS = 19
VOTE_SINGLE = 50
VOTE_TIE = 70
SINGLE_SUCC_RASN = 15
HIDDEN_INTER = 100
HIDDEN_NOINTER = 200


class Debug:

    def __init__(self):
        self.old = DEBUG

    def __enter__(self):
        global DEBUG
        DEBUG = True

    def __exit__(self, exc_type, exc_val, exc_tb):
        global DEBUG
        DEBUG = self.old
        return False


def router_changed(rupdates: Updates, rchanged: Set[Router], ichanged: Set[Interface]):
    rsucc: Router
    isucc: Interface
    for router in rupdates.changes:
        if not router.vrf:
            for isucc in router.succ:
                if isucc.pred:
                    ichanged.add(isucc)
        else:
            for rsucc in router.succ:
                if rsucc.succ:
                    rchanged.add(rsucc)
        for interface in router.interfaces:
            if interface.pred:
                ichanged.add(interface)
            for rpred in interface.pred:
                if rpred.succ:
                    rchanged.add(rpred)


def interface_changed(iupdates: Updates, rchanged: Set[Router], ichanged: Set[Interface]):
    rpred: Router
    ipred: Interface
    for interface in iupdates.changes:
        if not interface.vrf:
            for rpred in interface.pred:
                if rpred.succ:
                    rchanged.add(rpred)
        else:
            for ipred in interface.pred:
                if ipred.pred:
                    ichanged.add(ipred)


def graph_refinement(bdrmapit: Bdrmapit, routers: List[Router], interfaces: List[Interface], iterations: int = -1,
                     previous_updates: List[Tuple[dict, dict]] = None, create_changed=False, rupdates: Updates = None,
                     iupdates: Updates = None, iteration=0) -> Tuple[Updates, Updates]:
    rupdates = Updates() if rupdates is None else UpdatesView(rupdates)
    iupdates = Updates() if iupdates is None else UpdatesView(iupdates)
    rchanged: Set[Router] = set(routers)
    ichanged: Set[Interface] = set(interfaces)
    if previous_updates is None:
        previous_updates = []
    while iterations < 0 or iteration < iterations:
        Progress.message('********** Iteration {:,d} **********'.format(iteration), file=sys.stderr)
        annotate_routers(bdrmapit, rupdates, iupdates, routers=rchanged)
        if create_changed or iteration > 0:
            rchanged = set()
            router_changed(rupdates, rchanged, ichanged)
        rupdates.advance()
        annotate_interfaces(bdrmapit, rupdates, iupdates, interfaces=ichanged)
        ichanged = set()
        interface_changed(iupdates, rchanged, ichanged)
        iupdates.advance()
        if (rupdates, iupdates) in previous_updates:
            break
        previous_updates.append((dict(rupdates), dict(iupdates)))
        iteration += 1
    return rupdates, iupdates


def annotate_mpls(bdrmapit: Bdrmapit, routers: List[Router], rchanged: Updates):
    pb = Progress(len(routers), 'Annotating MPLS routers', increment=100000)
    for router in pb.iterator(routers):
        origins = Counter()
        for interface in router.interfaces:
            if interface.mpls:
                origins[interface.asn] += 1
        if len(origins) > 1:
            raise Exception('Not sure what to do with multiple origin ASes')
        if len(origins) == 1:
            asn = peek(origins)
            org = bdrmapit.as2org[asn]
            rchanged.add_update(router, asn, org, 2)


def router_heuristics(bdrmapit: Bdrmapit, router: Router, isucc: Interface, iasn: int, rupdates: Updates, iupdates: Updates):
    rsucc: Router = isucc.router
    rsucc_asn: int = bdrmapit.get_asn(rsucc, rupdates)
    succ_asn: int = iupdates.asn(isucc)
    if DEBUG:
        print('\tASN={}, RASN={}, IASN={} VRF={}'.format(isucc.asn, rsucc_asn, succ_asn, router.vrf))
    if isucc.asn == 0 or router.vrf:
        return rsucc_asn
    if isucc.asn <= -100:
        return iasn if iasn > 0 else -1
    if isucc.asn == iasn:
        return isucc.asn
    if rsucc_asn > 0 and rsucc_asn != isucc.asn:
        if DEBUG:
            print('\tThird party: Router={}, RASN={}'.format(rsucc.name, rsucc_asn))
        if isucc.org != bdrmapit.as2org[iasn]:
            if iasn == rsucc_asn or bdrmapit.bgp.rel(iasn, rsucc_asn):
                if DEBUG:
                    print('\tISUCC in Dests: {} in {}'.format(isucc.asn, router.dests))
                if isucc.asn not in router.dests:
                    return rsucc_asn
                elif bdrmapit.bgp.rel(isucc.asn, rsucc_asn) and not bdrmapit.bgp.rel(isucc.asn, iasn):
                    return rsucc_asn
    if succ_asn <= 0 or (0 < rsucc_asn != isucc.asn):
        return isucc.asn
    return succ_asn


def reallocated_test(bdrmapit: Bdrmapit, oasn, newasn):
    conesize = bdrmapit.bgp.conesize[newasn]
    if DEBUG:
        print('Reallocated Test: conesize={} < 5 and conesize={} < oldcone={} and not peer_rel({}, {}) = {}'.format(conesize, conesize, bdrmapit.bgp.conesize[oasn], newasn, oasn, bdrmapit.bgp.peer_rel(newasn, oasn)))
    return conesize <= 3 and conesize < bdrmapit.bgp.conesize[oasn] and not bdrmapit.bgp.peer_rel(newasn, oasn)


def reallocated(bdrmapit: Bdrmapit, router: Router, edges: Set[Interface], rupdates: Updates, succs: Counter, succ_origins: Dict[int, Set]):
    if router.nexthop and len(edges) > 1:
        same: DefaultDict[int, List[Interface]] = defaultdict(list)
        for s in edges:
            if s.asn in router.origins[s]:
                same[s.asn].append(s)
        if DEBUG:
            print('Same: {}'.format({k: [i.addr for i in v] for k, v in same.items()}))
        for oasn, isuccs in same.items():
            if len(isuccs) > 1:
                prefixes = {s.addr.rpartition('.')[0] for s in isuccs}
                if DEBUG:
                    print('Prefixes: {}'.format(prefixes))
                if len(prefixes) == 1:
                    rsuccs = {s.router for s in isuccs}
                    if all(bdrmapit.get_utype(rsucc, rupdates) < REALLOCATED_PREFIX for rsucc in rsuccs):
                        rasns = {bdrmapit.get_utype(rsucc, rupdates) for rsucc in rsuccs}
                        if DEBUG:
                            print('RASNs: {}'.format(rasns))
                        if len(rasns) > 1 or oasn in rasns:
                            mrdests = router.dests
                            if DEBUG:
                                if len(mrdests) < 5:
                                    print('Modified Dests: {}'.format(mrdests))
                                else:
                                    print('Modified Dests: {:,d} > 1'.format(len(mrdests)))
                            if len(mrdests) == 1:
                                rasns = mrdests
                        if len(rasns) == 1:
                            newasn = peek(rasns)
                            if newasn > 0 and newasn != oasn:
                                if reallocated_test(bdrmapit, oasn, newasn):
                                    num = succs.pop(oasn, 0)
                                    succs[newasn] = num
                                    succ_origins[newasn] = succ_origins[oasn]
                                    return REALLOCATED_PREFIX
    return 0


def hidden_asn(bdrmapit: Bdrmapit, iasn: int, asn: int, utype: int, votes: Dict[int, int]):
    intersection: Set[int] = bdrmapit.bgp.customers[iasn] & bdrmapit.bgp.providers[asn]
    intasn: int = None
    if len(intersection) == 1:
        intasn = peek(intersection)
        if DEBUG:
            print('Hidden: {}'.format(intasn))
    elif not intersection:
        intersection = bdrmapit.bgp.providers[iasn] & bdrmapit.bgp.customers[asn]
        if len(intersection) == 1:
            intasn = peek(intersection)
            if DEBUG:
                print('Hidden Reversed: {}'.format(intasn))
    if intasn is not None:
        interorg = bdrmapit.as2org[intasn]
        if interorg in {bdrmapit.as2org[vasn] for vasn in votes}:
            return asn, HIDDEN_NOINTER + utype
        return intasn, HIDDEN_INTER + utype
    if DEBUG:
        print('Missing: {}-{}'.format(iasn, asn))
    for sibasn in bdrmapit.as2org.siblings[asn]:
        if bdrmapit.bgp.rel(iasn, sibasn):
            return sibasn, 200000 + utype
    for sibasn in bdrmapit.as2org.siblings[iasn]:
        if bdrmapit.bgp.rel(sibasn, asn):
            return asn, 300000 + utype
            # return sibasn, 300000 + utype
    return iasn, HIDDEN_NOINTER + utype


def annotate_router(bdrmapit: Bdrmapit, router: Router, rupdates: Updates, iupdates: Updates):
    isucc: Interface

    # All routers have only a single interface -- no aliases
    iasn: int = router.interfaces[0].asn
    if DEBUG:
        print('IASN: {}'.format(iasn))

    utype = 0
    if DEBUG:
        print('Edges={}, NH={}'.format(len(router.succ), router.nexthop))
        print('MPLS?: {}'.format(any(i.mpls for i in router.interfaces)))

    # utype += reallocated(bdrmapit, router, edges, rupdates, succs, succ_origins)

    # Use heuristics to determine link votes
    succs = Counter()
    for isucc in router.succ:
        if DEBUG:
            print('Succ={}, ASN={}, Origins={}'.format(isucc.addr, isucc.asn, iasn))
        succ_asn = router_heuristics(bdrmapit, router, isucc, iasn, rupdates, iupdates)
        if DEBUG:
            print('Heuristic: {}'.format(succ_asn))
        if succ_asn > 0:
            succs[succ_asn] += 1
    if DEBUG:
        print('Succs: {}'.format(succs))

    # Deal specially with cases where there is only a single subsequent AS
    if len(succs) == 1 or len({bdrmapit.as2org[sasn] for sasn in succs}) == 1:
        sasn = peek(succs) if len(succs) == 1 else max(succs, key=lambda x: (bdrmapit.bgp.conesize[x], -x))
        # Subsequent AS = Interface AS
        if sasn == iasn:
            return sasn, utype + SINGLE_SUCC_ORIGIN

        # Subsequent AS is customer of interface AS
        if bdrmapit.bgp.customer_rel(sasn, iasn):
            if DEBUG:
                print('Provider: {}->{}'.format(iasn, sasn))
            return sasn, utype + SINGLE_SUCC_4

        # No relationship between interface AS and subsequent AS
        if not bdrmapit.bgp.rel(iasn, sasn) and bdrmapit.bgp.conesize[iasn] > bdrmapit.bgp.conesize[sasn]:
            return hidden_asn(bdrmapit, iasn, sasn, utype, {iasn: 1})

        # Not sure what I'm trying to do here
        for isucc in router.succ:
            supdate = iupdates[isucc]
            if supdate:
                sasn2 = supdate.asn
                itype = supdate.utype
                rasn = bdrmapit.get_asn(isucc.router, rupdates)
                if sasn2 == sasn and ((rasn == sasn and itype == 1) or rasn != sasn):
                    return sasn, utype + IUPDATE

        # Or here
        rasns = set()
        for isucc in router.succ:
            rasn = bdrmapit.get_asn(isucc.router, rupdates)
            rasns.add(rasn if rasn > 0 else sasn)
        if DEBUG:
            print('RASNS={}, SASN={}'.format(rasns, sasn))
        if sasn not in rasns:
            return sasn, utype + SINGLE_SUCC_RASN

        # Check if interface AS is customer of subsequent AS
        sasn = peek(succs)
        if bdrmapit.bgp.customer_rel(sasn, iasn):
            return sasn, utype + REMAINING_4

    # Create votes counter and add interface AS
    votes = Counter(succs)
    if iasn > 0:
        votes[iasn] += 1
    if DEBUG:
        print('Votes: {}'.format(votes))
    if not votes:
        return -1, -1

    if len(succs) > 1:
        noiasn = Counter(succs)
        noiasn[iasn] -= 1
        if len(noiasn) > 1 and all(v < 2 for v in noiasn.values()):
            if all(iasn == sasn or bdrmapit.as2org[iasn] == bdrmapit.as2org[sasn] or bdrmapit.bgp.rel(iasn, sasn) for sasn in succs):
                return iasn, 1000000
        if iasn not in succs:
            if all(bdrmapit.bgp.peer_rel(iasn, sasn) for sasn in succs):
                if votes[iasn] > max(votes.values()) / 2:
                    return iasn, utype + ALLPEER_SUCC
        if iasn in succs:
            if all(bdrmapit.bgp.peer_rel(iasn, sasn) or bdrmapit.bgp.provider_rel(sasn, iasn) for sasn in succs if sasn != iasn):
                if votes[iasn] > max(votes.values()) / 2:
                    return iasn, IASN_SUCC_HALF

    votes_rels: List[int] = [vasn for vasn in votes if vasn == iasn or bdrmapit.bgp.rel(iasn, vasn) or bdrmapit.as2org[iasn] == bdrmapit.as2org[vasn]]
    if DEBUG:
        print('Vote Rels: {}'.format(votes_rels))
    if len(votes_rels) < 2:
        asns = max_num(votes, key=votes.__getitem__)
        if DEBUG:
            print('ASNs: {}'.format(asns))
    else:
        for vasn in list(votes):
            if vasn not in votes_rels:
                for vr in votes_rels:
                    if bdrmapit.as2org[vr] == bdrmapit.as2org[vasn]:
                        votes[vr] += votes.pop(vasn, 0)
        asns = max_num(votes_rels, key=votes.__getitem__)
        othermax = max(votes, key=votes.__getitem__)
        if DEBUG:
            print('ASNs: {}'.format(asns))
            print('Othermax: {}'.format(othermax))
        if router.nexthop and votes[othermax] > votes[asns[0]] * 4:
            utype += 3000
            return othermax, utype

    if len(asns) == 1:
        asn = asns[0]
        utype += VOTE_SINGLE
    else:
        asn = min(asns, key=lambda x: (bdrmapit.bgp.conesize[x], -x))
        utype += VOTE_TIE
    if iasn > 0 and asn != iasn and not bdrmapit.bgp.rel(iasn, asn):
        return hidden_asn(bdrmapit, iasn, asn, utype, votes)
    return asn, utype


def annotate_routers(bdrmapit: Bdrmapit, rupdates: Updates, iupdates: Updates, routers: Collection[Router], increment=100000):
    pb = Progress(len(routers), 'Annotating routers', increment=increment)
    for router in pb.iterator(routers):
        asn, utype = annotate_router(bdrmapit, router, rupdates, iupdates)
        rupdates.add_update(router, asn, bdrmapit.as2org[asn], utype)
    return rupdates


def annotate_interface(bdrmapit: Bdrmapit, interface, rupdates: Updates):
    edges: Dict[Router, int] = interface.pred
    # priority = bdrmapit.graph.iedges.priority[interface]
    if DEBUG:
        # log.debug('Edges: {}'.format(edges))
        print('VRF: {}'.format(interface.vrf))
    votes = Counter()
    for rpred, num in edges.items():
        asn = bdrmapit.get_asn(rpred, rupdates)
        if DEBUG:
            print('Router={}, RASN={}'.format(rpred.name, asn))
        votes[asn] += num
    if DEBUG:
        print('Votes: {}'.format(votes))
    if len(votes) == 1:
        return peek(votes), 1 if len(edges) > 1 else 0
    asns = max_num(votes, key=votes.__getitem__)
    if DEBUG:
        print('MaxNum: {}'.format(asns))
    rels = [asn for asn in asns if interface.asn == asn or bdrmapit.bgp.rel(interface.asn, asn)]
    if not rels:
        rels = asns
    if DEBUG:
        print('Rels: {}'.format(rels))
        print('Sorted Rels: {}'.format(sorted(rels, key=lambda x: (
        x != interface.asn, -bdrmapit.bgp.provider_rel(interface.asn, x), -bdrmapit.bgp.conesize[x], x))))
    # asn = max(asns, key=lambda x: (x == interface.asn, bdrmapit.bgp.conesize[x], -x))
    asn = min(rels, key=lambda x: (x != interface.asn, -bdrmapit.bgp.provider_rel(interface.asn, x), -bdrmapit.bgp.conesize[x], x))
    utype = 1 if len(asns) == 1 and len(edges) > 1 else 2
    return asn, utype


def annotate_interface_orig(bdrmapit: Bdrmapit, interface, rupdates: Updates):
    edges: Dict[Router, int] = interface.pred
    # priority = bdrmapit.graph.iedges.priority[interface]
    if DEBUG:
        # log.debug('Edges: {}'.format(edges))
        print('VRF: {}'.format(interface.vrf))
    votes = Counter()
    for rpred, num in edges.items():
        asn = rpred.interfaces[0].asn
        if DEBUG:
            print('Router={}, RASN={}'.format(rpred.name, asn))
        votes[asn] += num
    if DEBUG:
        print('Votes: {}'.format(votes))
    if len(votes) == 1:
        return peek(votes), 1 if len(edges) > 1 else 0
    asns = max_num(votes, key=votes.__getitem__)
    if DEBUG:
        print('MaxNum: {}'.format(asns))
    rels = [asn for asn in asns if interface.asn == asn or bdrmapit.bgp.rel(interface.asn, asn)]
    if not rels:
        rels = asns
    if DEBUG:
        print('Rels: {}'.format(rels))
        print('Sorted Rels: {}'.format(sorted(rels, key=lambda x: (
        x != interface.asn, -bdrmapit.bgp.provider_rel(interface.asn, x), -bdrmapit.bgp.conesize[x], x))))
    # asn = max(asns, key=lambda x: (x == interface.asn, bdrmapit.bgp.conesize[x], -x))
    asn = min(rels, key=lambda x: (x != interface.asn, -bdrmapit.bgp.provider_rel(interface.asn, x), -bdrmapit.bgp.conesize[x], x))
    utype = 1 if len(asns) == 1 and len(edges) > 1 else 2
    return asn, utype


def annotate_interface_superrouter(bdrmapit: Bdrmapit, interface, rupdates: Updates, iupdates: Updates):
    asn1, utype1 = annotate_interface(bdrmapit, interface, rupdates)
    asn2, utype2 = annotate_interface_orig(bdrmapit, interface, rupdates)
    if asn1 == asn2:
        return asn1, utype1
    edges: Dict[Router, int] = interface.pred
    if len(edges) > 1:
        newrouter = Router('tmp')
        newrouter.interfaces.extend({interface for router in edges for interface in router.interfaces})
        newrouter.nexthop = any(router.nexthop for router in edges)
        newrouter.vrf = False
        for router in edges:
            if router.nexthop == newrouter.nexthop:
                newrouter.succ.update(router.succ)
                for succ in router.origins:
                    origins = newrouter.origins.get(succ, set())
                    origins.update(router.origins[succ])
                    newrouter.origins[succ] = origins
            newrouter.dests.update(router.dests)
    else:
        newrouter = peek(edges)
    return annotate_router(bdrmapit, newrouter, rupdates, iupdates)


def annotate_interfaces(bdrmapit: Bdrmapit, rupdates: Updates, iupdates: Updates, interfaces: Collection[Interface]):
    pb = Progress(len(interfaces), 'Adding links', increment=10000)
    for interface in pb.iterator(interfaces):
        if interface.asn >= 0:
            # asn, utype = annotate_interface(bdrmapit, interface, rupdates, iupdates)
            asn, utype = annotate_interface(bdrmapit, interface, rupdates)
            iupdates.add_update(interface, asn, bdrmapit.as2org[asn], utype)
    return iupdates
