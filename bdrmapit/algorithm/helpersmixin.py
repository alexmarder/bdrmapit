from typing import Optional

from traceutils.bgp.bgp import BGP

from bdrmapit.algorithm.updates_dict import Updates


class HelpersMixin:

    rupdates: Optional[Updates] = None
    bgp: Optional[BGP] = None

    def multi_customers(self, asns):
        return {customer for asn in asns for customer in self.bgp.customers[asn]}

    def multi_peers(self, asns):
        return {peer for asn in asns for peer in self.bgp.peers[asn]}

    def multi_providers(self, asns):
        return {provider for asn in asns for provider in self.bgp.providers[asn]}

    def any_rels(self, asn, others):
        for other in others:
            if self.bgp.rel(asn, other):
                return True
        return False
