import json
import os
import re
import sqlite3
from collections import Counter
from typing import Set, Collection

import pandas as pd
from traceutils.file2 import fopen2, fopen

from traceutils.progress import Progress
from traceutils.radix.ip2as import IP2AS

from bdrmapit.algorithm.algorithm import Bdrmapit
from bdrmapit.algorithm.updates_dict import Updates, UpdateObj
from bdrmapit.graph.node import Interface, Router
from scripts.traceparser import ParseResults


class Save:

    def __init__(self, filename, bdrmapit: Bdrmapit, rupdates: Updates = None, iupdates: Updates = None, replace=True):
        self.filename = filename
        self.bdrmapit = bdrmapit
        self.rupdates = rupdates if rupdates is not None else bdrmapit.rupdates
        self.iupdates = iupdates if iupdates is not None else bdrmapit.iupdates
        exists = os.path.exists(filename)
        if not exists or replace:
            if exists:
                os.remove(filename)
            dir_path = os.path.dirname(os.path.realpath(__file__))
            with open(os.path.join(dir_path, 'tables.sql')) as f:
                script = f.read()
            con = sqlite3.connect(filename)
            cur = con.cursor()
            cur.executescript(script)
            con.commit()
            con.close()

    def save_annotations(self):
        interface: Interface
        values = []
        pb = Progress(len(self.bdrmapit.graph.interfaces), 'Writing annotations', increment=100000)
        con = sqlite3.connect(self.filename)
        cur = con.cursor()
        for interface in pb.iterator(self.bdrmapit.graph.interfaces.values()):
            addr = interface.addr
            router: Router = interface.router
            rupdate: UpdateObj = self.rupdates[router]
            iupdate: UpdateObj = self.iupdates[interface]
            if rupdate is None:
                rasn = -1
                rorg = -1
                rtype = -1
            else:
                rasn = rupdate.asn
                rorg = rupdate.org
                rtype = rupdate.utype
            if iupdate is None or interface.org != rorg:
                iasn = interface.asn
                iorg = interface.org
                itype = -1 if iupdate is None else 0
            else:
                iasn = iupdate.asn
                iorg = iupdate.org
                itype = iupdate.utype
            phop = bool(interface.pred)
            row = {'addr': addr, 'router': router.name, 'asn': rasn, 'org': rorg, 'conn_asn': iasn, 'conn_org': iorg, 'echo': False, 'nexthop': router.nexthop, 'phop': phop, 'rtype': rtype, 'itype': itype, 'iasn': interface.asn}
            # if addr == '202.68.67.250':
            #     print(row)
            values.append(row)
            if len(values) > 100000:
                cur.executemany('INSERT INTO annotation (addr, router, asn, org, conn_asn, conn_org, echo, nexthop, phop, rtype, itype, iasn) VALUES (:addr, :router, :asn, :org, :conn_asn, :conn_org, :echo, :nexthop, :phop, :rtype, :itype, :iasn)', values)
                con.commit()
                values.clear()
        if values:
            cur.executemany('INSERT INTO annotation (addr, router, asn, org, conn_asn, conn_org, echo, nexthop, phop, rtype, itype, iasn) VALUES (:addr, :router, :asn, :org, :conn_asn, :conn_org, :echo, :nexthop, :phop, :rtype, :itype, :iasn)', values)
            con.commit()
        cur.close()
        con.close()

    def save_echos(self, echos, ip2as, as2org):
        interface: Interface
        values = []
        con = sqlite3.connect(self.filename)
        cur = con.cursor()
        pb = Progress(len(echos), 'Writing echos', increment=100000)
        for addr in pb.iterator(echos):
            rasn = iasn = ip2as[addr]
            rorg = iorg = as2org[rasn]
            rtype = 0
            itype = 0
            row = {'addr': addr, 'router': addr, 'asn': rasn, 'org': rorg, 'conn_asn': iasn, 'conn_org': iorg, 'echo': True, 'rtype': rtype, 'itype': itype}
            values.append(row)
            if len(values) > 100000:
                cur.executemany(
                    'INSERT INTO annotation (addr, router, asn, org, conn_asn, conn_org, echo, rtype, itype) VALUES (:addr, :router, :asn, :org, :conn_asn, :conn_org, :echo, :rtype, :itype)',
                    values)
                con.commit()
                values.clear()
        if values:
            cur.executemany('INSERT INTO annotation (addr, router, asn, org, conn_asn, conn_org, echo, rtype, itype) VALUES (:addr, :router, :asn, :org, :conn_asn, :conn_org, :echo, :rtype, :itype)', values)
            con.commit()
        cur.close()
        con.close()

    def save_ixps(self):
        values = []
        for router in self.bdrmapit.routers_succ:
            conn_asn = self.rupdates[router].asn
            conn_org = self.bdrmapit.as2org[conn_asn]
            for isucc in router.succ:
                if isucc.asn <= -100:
                    pid = (isucc.asn * -1) - 100
                    rsucc = isucc.router
                    asn = self.rupdates[rsucc].asn
                    org = self.bdrmapit.as2org[asn]
                    value = {'addr': isucc.addr, 'router': router.name, 'asn': asn, 'org': org, 'conn_asn': conn_asn, 'conn_org': conn_org, 'pid': pid, 'nexthop': router.nexthop}
                    values.append(value)
        con = sqlite3.connect(self.filename)
        cur = con.cursor()
        cur.executemany('INSERT INTO ixp (addr, router, asn, org, conn_asn, conn_org, pid, nexthop) VALUES (:addr, :router, :asn, :org, :conn_asn, :conn_org, :pid, :nexthop)', values)
        con.commit()
        con.close()

    def save_links(self):
        values = []
        for isucc in self.bdrmapit.interfaces_pred:
            rsucc = isucc.router
            asn = self.rupdates[rsucc].asn
            org = self.bdrmapit.as2org[asn]
            ixp = isucc.asn <= -100
            for router in isucc.pred:
                conn_asn = self.rupdates[router].asn
                conn_org = self.bdrmapit.as2org[conn_asn]
                if conn_org != org:
                    value = {'addr': isucc.addr, 'router': router.name, 'asn': asn, 'org': org, 'conn_asn': conn_asn, 'conn_org': conn_org, 'ixp': ixp}
                    values.append(value)
        con = sqlite3.connect(self.filename)
        cur = con.cursor()
        cur.executemany('INSERT INTO link (addr, router, asn, org, conn_asn, conn_org, ixp) VALUES (:addr, :router, :asn, :org, :conn_asn, :conn_org, :ixp)', values)
        con.commit()
        con.close()

    def save_caches(self):
        values = []
        for isucc, iupdate in self.bdrmapit.caches.items():
            rsucc = isucc.router
            asn = self.rupdates[rsucc].asn
            org = self.bdrmapit.as2org[asn]
            ixp = isucc.asn <= -100
            conn_asn = iupdate.asn
            conn_org = iupdate.org
            if conn_org != org:
                value = {'addr': isucc.addr, 'router': rsucc.name, 'asn': asn, 'org': org, 'conn_asn': conn_asn, 'conn_org': conn_org, 'ixp': ixp}
                values.append(value)
        con = sqlite3.connect(self.filename)
        cur = con.cursor()
        cur.executemany('INSERT INTO cache (addr, router, asn, org, conn_asn, conn_org, ixp) VALUES (:addr, :router, :asn, :org, :conn_asn, :conn_org, :ixp)', values)
        con.commit()
        con.close()

    def extras(self, parseres: ParseResults, ip2as: IP2AS):
        values = []
        loops = set()
        for addrs in parseres.loopadjs:
            for addr in addrs:
                if addr not in self.bdrmapit.graph.interfaces:
                    loops.add(addr)
                    asn = ip2as[addr]
                    org = self.bdrmapit.as2org[asn]
                    row = {'addr': addr, 'asn': asn, 'reason': 'loop'}
                    values.append(row)
        echos = set()
        for addr in parseres.echos:
            if addr not in loops and addr not in self.bdrmapit.graph.interfaces:
                echos.add(addr)
                asn = ip2as[addr]
                org = self.bdrmapit.as2org[asn]
                row = {'addr': addr, 'asn': asn, 'reason': 'echo'}
                values.append(row)
        con = sqlite3.connect(self.filename)
        cur = con.cursor()
        cur.executemany('INSERT INTO excluded (addr, asn, org, reason) VALUES (:addr, :asn, :org, :reason)', values)
        con.commit()
        con.close()

    def save_node_as(self, filename, include_all=False):
        with fopen(filename, 'wt') as f:
            for router in self.bdrmapit.graph.routers.values():
                if router.name[0] == 'N':
                    update = self.bdrmapit.rupdates[router]
                    if update.asn <= 0:
                        continue
                    if update.utype == 1:
                        method = 'interfaces'
                    elif update.utype < 10:
                        method = 'last_hop'
                    else:
                        method = 'refinement'
                    f.write('node.AS {}:  {} {}\n'.format(router.name, update.asn, method))

def isregexasn(utype):
    return (utype & 0xff00) == 0xff00

def isregexorg(utype):
    return utype & 0xfe00 == 0xfe00

def regexreasons(utype):
    reasons = []
    if utype == 0xff00:
        reasons.append('noinfo')
    if utype & 0x0001:
        reasons.append('origin')
    if utype & 0x0002:
        reasons.append('subsequent')
    if utype & 0x0004:
        reasons.append('dest')
    if utype & 0x0008:
        reasons.append('provider')
    if not reasons:
        print(utype)
    return reasons

class ITDK:
    def __init__(self, bdrmapit: Bdrmapit, rupdates: Updates = None):
        self.bdrmapit = bdrmapit
        self.rupdates = rupdates if rupdates is not None else bdrmapit.rupdates

    def default_reason(self, router, update: UpdateObj):
        if update.asn <= 0:
            return 'unknown'
        elif router.hints and update.asn in router.hints:
            return 'as-hints'
        elif router.succ:
            return 'refinement'
        elif router.dests:
            return 'lasthop'
        else:
            return 'origins'

    def hint_reason(self, router, update: UpdateObj):
        utype = update.utype
        if isregexasn(utype):
            reasons = regexreasons(utype)
            reason = '|'.join(reasons)
        elif isregexorg(utype):
            reasons = regexreasons(utype)
            reason = '|'.join(reasons)
        else:
            reason = 'normal'
        return reason

    def write_nodes(self, filename, reason_func=None, include_all=False):
        if reason_func is None:
            reason_func = self.default_reason
        with fopen2(filename, 'wt') as f:
            for name, router in self.bdrmapit.graph.routers.items():
                if include_all or name[0] == 'N':
                    update = self.rupdates[router]
                    asn = update.asn
                    reason = reason_func(router, update)
                    f.write('node.AS\t{}\t{}\t{}\n'.format(name, asn, reason))

    def node_info(self, filename):
        with fopen2(filename, 'wt') as f:
            for name, router in self.bdrmapit.graph.routers.items():
                if name[0] == 'N':
                    update = self.rupdates[router]
                    if not router.hints:
                        hints = []
                    else:
                        hints = [int(h) for h in router.hints]
                    if isregexasn(update.utype):
                        restype = 'asn'
                    elif isregexorg(update.utype):
                        restype = 'org'
                    else:
                        restype = None
                    if restype is not None:
                        reasons = regexreasons(update.utype)
                    else:
                        reasons = []
                    origins = dict(Counter(interface.asn if interface.asn >= 0 else -100 for interface in router.interfaces))
                    succs = dict(Counter(interface.asn if interface.asn >= 0 else -100 for interface in router.succ))
                    dests = list(router.dests)
                    d = {'node': name, 'asn': int(update.asn), 'hints': hints, 'match': restype, 'reasons': reasons,
                         'origins': origins, 'subsequent': succs, 'dests': dests}
                    f.write(json.dumps(d) + '\n')

class Analyze:
    def __init__(self, bdrmapit: Bdrmapit):
        self.bdrmapit = bdrmapit

    def todf(self, interfaces: Collection[Interface], rupdates: Updates = None):
        if rupdates is None:
            rupdates = self.bdrmapit.rupdates
        rows = []
        for interface in interfaces:
            router = interface.router
            update = rupdates[router]
            asn = update.asn
            org = self.bdrmapit.as2org[asn]
            rtype = update.utype
            row = {'addr': interface.addr, 'asn': asn, 'org': org, 'rtype': rtype}
            rows.append(row)
        return pd.DataFrame(rows)

    def todf_addrs(self, addrs, *args, **kwargs):
        interfaces = [self.bdrmapit.graph.interfaces[addr] for addr in addrs if addr in self.bdrmapit.graph.interfaces]
        return self.todf(interfaces, *args, **kwargs)

class Test:
    def __init__(self, bdrmapit, names, file, rupdates: Updates = None, iupdates: Updates = None):
        self.bdrmapit = bdrmapit
        self.rupdates = rupdates if rupdates is not None else bdrmapit.rupdates
        self.iupdates = iupdates if iupdates is not None else bdrmapit.iupdates
        self.names = names
        self.file = file

    def create_tags(self):
        interre = re.compile(r'([a-z]+)\..*\.ntwk\.msn\.net')
        tags = {}
        with open(self.file) as f:
            for line in f:
                if line.startswith('#'):
                    continue
                tag, *asns = line.split()
                if asns:
                    tags[tag] = tuple({int(asn) for asn in asns})
        valmap = {}
        for addr, name in self.names.items():
            m = interre.match(name)
            if m:
                tag = m.group(1)
                if tag in tags:
                    valmap[addr] = tags[tag]
        self.valmap = valmap

    def todf(self, addrs=None):
        if addrs is not None:
            interfaces: Set[Interface] = {self.bdrmapit.graph.interfaces[a] for a in addrs if a in self.bdrmapit.graph.interfaces}
        else:
            interfaces: Set[Interface] = self.bdrmapit.graph.interfaces.values()
        values = []
        for interface in interfaces:
            addr = interface.addr
            router: Router = interface.router
            rupdate: UpdateObj = self.rupdates[router]
            iupdate: UpdateObj = self.iupdates[interface]
            if rupdate is None:
                rasn = -1
                rorg = -1
                rtype = -1
            else:
                rasn = rupdate.asn
                rorg = rupdate.org
                rtype = rupdate.utype
            if iupdate is None or interface.org != rorg:
                iasn = interface.asn
                iorg = interface.org
                itype = -1 if iupdate is None else 0
            else:
                iasn = iupdate.asn
                iorg = iupdate.org
                itype = iupdate.utype
            row = {'addr': addr, 'router': router.name, 'asn': rasn, 'org': rorg, 'conn_asn': iasn, 'conn_org': iorg,
                   'rtype': rtype, 'itype': itype}
            values.append(row)
        return pd.DataFrame(values)

    def ixps(self, start_asn=None):
        values = []
        seen = set()
        for router in self.bdrmapit.routers_succ:
            conn_asn = self.rupdates[router].asn
            if conn_asn != start_asn:
                continue
            conn_org = self.bdrmapit.as2org[conn_asn]
            for isucc in router.succ:
                if isucc.asn <= -100:
                    if isucc.addr in seen:
                        continue
                    seen.add(isucc.addr)
                    pid = (isucc.asn * -1) - 100
                    rsucc = isucc.router
                    asn = self.rupdates[rsucc].asn
                    org = self.bdrmapit.as2org[asn]
                    value = {'addr': isucc.addr, 'router': router.name, 'asn': asn, 'org': org, 'conn_asn': conn_asn, 'conn_org': conn_org, 'pid': pid}
                    values.append(value)
        return pd.DataFrame(values)
