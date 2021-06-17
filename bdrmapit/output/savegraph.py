import json
import os.path
import sqlite3
from sqlite3 import Connection
from typing import Set, Dict, Any

from traceutils.progress import Progress

from bdrmapit.algorithm.algorithm import Bdrmapit
from bdrmapit.graph.node import Router, Interface

def srows(router: Router, add_preds=False, add_origins=False):
    rows = []
    for s in router.succ:
        row = {'addr': s.addr, 'router': s.router.name}
        if add_preds:
            row['pred'] = prows(s, add_succs=False)
        if add_origins:
            row['origins'] = list(router.origins[s])
        rows.append(row)
    return rows

def prows(iface: Interface, add_succs=False):
    rows = []
    for p, num in iface.pred.items():
        row = {'router': p.name, 'num': num}
        if add_succs:
            row['succ'] = srows(p, add_preds=False)
        rows.append(row)
    return rows

def insert(con: Connection, values):
    con.executemany('INSERT INTO graph (addr, graph) VALUES (:addr, :graph)', values)
    con.commit()
    values.clear()

def savegraph(bdrmapit: Bdrmapit, filename, replace=True):
    exists = os.path.exists(filename)
    if not exists or replace:
        if exists:
            os.remove(filename)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, 'graph.sql')) as f:
            script = f.read()
        con = sqlite3.connect(filename)
        cur = con.cursor()
        cur.executescript(script)
        con.commit()
    else:
        con = sqlite3.connect(filename)
    values = []
    pb = Progress(len(bdrmapit.graph.interfaces), increment=100000)
    for interface in pb.iterator(bdrmapit.graph.interfaces.values()):
        router: Router = interface.router
        succs = json.dumps(srows(router, add_preds=True, add_origins=True))
        preds = json.dumps(prows(interface, add_succs=True))
        row = {'addr': interface.addr, 'router': router.name, 'router_info': succs, 'iface_info': preds}
        values.append(row)
        if len(values) >= 100000:
            insert(con, values)
    if values:
        insert(con, values)
