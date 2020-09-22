from collections import Counter
from itertools import chain
from typing import Optional

from traceutils.as2org.as2org import AS2Org
from traceutils.bgp.bgp import BGP
from traceutils.utils.utils import peek

from bdrmapit.algorithm.updates_dict import Updates
from bdrmapit.graph.node import Router
from bdrmapit.algorithm import debug


class RegexMixin:

    bgp: Optional[BGP] = None
    as2org: Optional[AS2Org] = None
    rupdates: Optional[Updates] = None

    def hidden_provider_hint(self, router):
        sasns = {succ.asn for succ in router.succ if succ.asn > 0}
        providers = {pasn for sasn in chain(sasns, router.dests) for pasn in self.bgp.providers[sasn]}
        provinter = providers & router.hints
        if len(provinter) == 1:
            utype = 0xff08
            return peek(provinter), utype
        return -1, -1

    # def hidden_provider_hint(self, router):
    #     iasns = {interface.asn for interface in router.interfaces if interface.asn > 0}
    #     if not iasns:
    #         iasns = set()
    #         for interface in router.interfaces:
    #             for pred in interface.pred:
    #                 update = self.rupdates[pred]
    #                 if update is not None:
    #                     iasn = update.asn
    #                     if iasn > 0:
    #                         iasns.add(iasn)
    #     sasns = {succ.asn for succ in router.succ if succ.asn > 0}
    #     provsucc = {provider for asn in sasns for provider in self.bgp.providers[asn]}
    #     customers = {customer for asn in iasns for customer in self.bgp.customers[asn]}
    #     provcust = provsucc & customers
    #     provinter = provcust & router.hints
    #     if not provinter:
    #         provdest = {provider for asn in router.dests for provider in self.bgp.providers[asn]}
    #         provcust = provdest & customers
    #         provinter = provcust & router.hints
    #     if len(provinter) == 1:
    #         utype = 0xff08
    #         return peek(provinter), utype
    #     return -1, -1

    def annotate_router_hint(self, router: Router, use_provider=False):
        utype = 0
        if debug.DEBUG: print('Hints: {}'.format(router.hints))
        # iasns = {interface.asn for interface in router.interfaces if interface.asn > 0}
        sasns = Counter(succ.asn for succ in router.succ if succ.asn > 0)
        possible = sasns.keys() | router.dests
        if debug.DEBUG:
            # print('IASNs: {}'.format(iasns))
            print('SASNs: {}'.format(sasns))
            print('Dests: {}'.format(router.dests))
            print('{} in possible: {}'.format(router.hints, bool(router.hints & possible)))
        if not possible and len(router.hints) == 1:
            utype = 0xff00
            return peek(router.hints), utype
        intersection = possible & router.hints
        if len(intersection) == 1:
            # print(utype)
            # if router.hints & iasns:
            #     utype |= 0xff01
            if router.hints & sasns.keys():
                utype |= 0xff02
            if router.hints & router.dests:
                utype |= 0xff04
            # print(utype)
            return peek(intersection), utype
        elif len(intersection) > 2:
            return -1, utype
        posorgs = {self.as2org[asn] for asn in possible}
        hintorgs = {self.as2org[asn] for asn in router.hints}
        interorgs = posorgs & hintorgs
        if debug.DEBUG:
            print('{} in possible orgs: {}'.format(hintorgs, bool(hintorgs & posorgs)))
        if interorgs:
            # if hintorgs & {self.as2org[asn] for asn in iasns}:
            #     utype |= 0xfe01
            if hintorgs & {self.as2org[asn] for asn in sasns}:
                utype |= 0xfe02
            if hintorgs & {self.as2org[asn] for asn in router.dests}:
                utype |= 0xfe04
            return peek(router.hints), utype
        if use_provider:
            asn, utype = self.hidden_provider_hint(router)
            if asn > 0:
                return asn, utype
        return 0, utype
