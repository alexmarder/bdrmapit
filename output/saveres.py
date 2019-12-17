import os
import sqlite3

from traceutils.progress import Progress
from traceutils.radix.ip2as import IP2AS

from algorithm.algorithm import Bdrmapit
from bdrmapit_parser.algorithm.updates_dict import Updates, UpdateObj
from bdrmapit_parser.graph.node import Interface, Router
from traceparser import ParseResults


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
            row = {'addr': addr, 'router': router.name, 'asn': rasn, 'org': rorg, 'conn_asn': iasn, 'conn_org': iorg, 'rtype': rtype, 'itype': itype}
            values.append(row)
        con = sqlite3.connect(self.filename)
        con.executemany('INSERT INTO annotation (addr, router, asn, org, conn_asn, conn_org, rtype, itype) VALUES (:addr, :router, :asn, :org, :conn_asn, :conn_org, :rtype, :itype)', values)
        con.commit()
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
                    value = {'addr': isucc.addr, 'router': router.name, 'asn': asn, 'org': org, 'conn_asn': conn_asn, 'conn_org': conn_org, 'pid': pid}
                    values.append(value)
        con = sqlite3.connect(self.filename)
        cur = con.cursor()
        cur.executemany('INSERT INTO ixp (addr, router, asn, org, conn_asn, conn_org, pid) VALUES (:addr, :router, :asn, :org, :conn_asn, :conn_org, :pid)', values)
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

    def save_node_as(self, filename):
        with open(filename, 'w') as f:
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
