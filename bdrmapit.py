#!/usr/bin/env python
import json
import os
import sqlite3
import sys
from argparse import ArgumentParser

from jsonschema import validate
from traceutils.as2org import AS2Org
from traceutils.bgp import BGP
from traceutils.progress import Progress
from traceutils.radix.ip2as import create_table

from algorithm.algorithm_alias import Bdrmapit
from container.container import Container
from bdrmapit_parser.algorithm.updates_dict import UpdateObj, Updates
from bdrmapit_parser.graph.node import Interface, Router
import traceparser as tp
from traceparser import TraceFile, OutputType

def save_annotations(filename, bdrmapit: Bdrmapit, rupdates=None, iupdates=None):
    if os.path.exists(filename):
        os.remove(filename)
    con = sqlite3.connect(filename)
    con.execute('''CREATE TABLE annotation(
        addr TEXT,
        router TEXT,
        asn INT,
        org TEXT,
        conn_asn INT,
        conn_org TEXT,
        rtype INT,
        itype INT
    )''')
    if rupdates is None:
        rupdates = bdrmapit.rupdates
    if iupdates is None:
        iupdates = bdrmapit.iupdates
    interface: Interface
    values = []
    pb = Progress(len(bdrmapit.graph.interfaces), 'Writing annotations', increment=100000)
    for interface in pb.iterator(bdrmapit.graph.interfaces.values()):
        addr = interface.addr
        router: Router = interface.router
        rupdate: UpdateObj = rupdates[router]
        iupdate: UpdateObj = iupdates[interface]
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
    con.executemany('insert into annotation (addr, router, asn, org, conn_asn, conn_org, rtype, itype) values (:addr, :router, :asn, :org, :conn_asn, :conn_org, :rtype, :itype)', values)
    con.commit()

def save_ixps(filename, bdrmapit: Bdrmapit, rupdates: Updates = None):
    if rupdates is None:
        rupdates = bdrmapit.rupdates
    con = sqlite3.connect(filename)
    cur = con.cursor()
    cur.execute('drop table if EXISTS ixp')
    cur.execute('''CREATE TABLE IF NOT EXISTS ixp(
        addr TEXT,
        router TEXT,
        asn INT,
        org TEXT,
        conn_asn INT,
        conn_org TEXT,
        pid INT
    )''')
    values = []
    for router in bdrmapit.routers_succ:
        conn_asn = rupdates[router].asn
        conn_org = bdrmapit.as2org[conn_asn]
        for isucc in router.succ:
            if isucc.asn <= -100:
                pid = (isucc.asn * -1) - 100
                rsucc = isucc.router
                asn = rupdates[rsucc].asn
                org = bdrmapit.as2org[asn]
                value = {'addr': isucc.addr, 'router': router.name, 'asn': asn, 'org': org, 'conn_asn': conn_asn, 'conn_org': conn_org, 'pid': pid}
                values.append(value)
    cur.executemany('insert into ixp (addr, router, asn, org, conn_asn, conn_org, pid) VALUES (:addr, :router, :asn, :org, :conn_asn, :conn_org, :pid)', values)
    con.commit()

def save_node_as(filename, bdrmapit: Bdrmapit):
    with open(filename, 'w') as f:
        for router in bdrmapit.graph.routers.values():
            if router.name[0] == 'N':
                update = bdrmapit.rupdates[router]
                if update.asn <= 0:
                    continue
                if update.utype == 1:
                    method = 'interfaces'
                elif update.utype < 10:
                    method = 'last_hop'
                else:
                    method = 'refinement'
                f.write('node.AS {} {} {}\n'.format(router.name, update.asn, method))

def main():
    parser = ArgumentParser()
    parser.add_argument('-o', '--output', required=True, help='Output filename for sqlite3 output.')
    parser.add_argument('-n', '--nodes-as', help='Nodes to AS mapping filename.')
    parser.add_argument('-c', '--config', required=True, help='JSON config file in accordance with schema.json')
    parser.add_argument('-g', '--graph', help='Graph pickle object created by --graph-only.')
    parser.add_argument('--graph-only', action='store_true', help='Only create the graph, then save it to the specified file.')
    args = parser.parse_args()

    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.json')) as f:
        schema = json.load(f)
    with open(args.config) as f:
        config = json.load(f)
    if not args.graph_only:
        schema['required'].extend(['as2org', 'as-rels'])
    validate(config, schema)

    ip2as = create_table(config['ip2as'])
    as2org = AS2Org(config['as2org']['as2org'], config['as2org'].get('additional'))

    if 'graph' in config:
        sys.stdout.write('Unpickling graph.')
        prep = Container.load(config['graph'], ip2as, as2org)
        sys.stdout.write(' Done.\n')
    elif args.graph:
        sys.stdout.write('Unpickling graph.')
        prep = Container.load(args.graph, ip2as, as2org)
        sys.stdout.write(' Done.\n')
    else:
        if 'warts' not in config and 'atlas' not in config and 'atlas-odd' not in config:
            print('Either "warts", "atlas" or both must be specified in the configuration json.', file=sys.stderr)
            return
        files = []
        if 'warts' in config:
            warts = config['warts']
            if 'files' in warts:
                with open(warts['files']) as f:
                    files.extend(TraceFile(line.strip(), OutputType.WARTS) for line in f)
            if 'files-list' in warts:
                files.extend(TraceFile(file, OutputType.WARTS) for file in warts['files-list'])
        if 'atlas' in config:
            atlas = config['atlas']
            if 'files' in atlas:
                with open(atlas['files']) as f:
                    files.extend(TraceFile(line.strip(), OutputType.ATLAS) for line in f)
            if 'files-list' in atlas:
                files.extend(TraceFile(file, OutputType.ATLAS) for file in atlas['files-list'])
        if 'atlas-odd' in config:
            atlas = config['atlas-odd']
            if 'files' in atlas:
                with open(atlas['files']) as f:
                    files.extend(TraceFile(line.strip(), OutputType.ATLAS_ODD) for line in f)
            if 'files-list' in atlas:
                files.extend(TraceFile(file, OutputType.ATLAS_ODD) for file in atlas['files-list'])
        Progress.message('Files: {:,d}'.format(len(files)))

        parseres = tp.run(files, ip2as, config['processes'])
        if args.graph_only:
            parseres.dump(args.output)
            return
        prep = Container(ip2as, as2org, parseres)

    bgp = BGP(config['as-rels']['rels'], config['as-rels']['cone'])

    nodes_file = config.get('aliases')
    graph = prep.construct(nodes_file=nodes_file)

    bdrmapit = Bdrmapit(graph, as2org, bgp, strict=False)
    bdrmapit.set_dests()
    bdrmapit.annotate_lasthops()
    bdrmapit.graph_refinement(bdrmapit.routers_succ, bdrmapit.interfaces_pred, iterations=config.get('max_iterations', 10))

    save_annotations(args.output, bdrmapit)
    save_ixps(args.output, bdrmapit)
    if args.nodes_as:
        save_node_as(args.nodes_as, bdrmapit)

if __name__ == '__main__':
    main()
