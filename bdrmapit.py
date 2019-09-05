#!/usr/bin/env python
import json
import os
import pickle
import sqlite3
import sys
from argparse import ArgumentParser

from jsonschema import validate
from traceutils.as2org.as2org import AS2Org
from traceutils.bgp.bgp import BGP
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import create_table, IP2AS

from algorithm.algorithm_alias import Bdrmapit
from algorithm.parse_results_container import Container
from bdrmapit_parser.algorithm.updates_dict import UpdateObj
from bdrmapit_parser.graph.node import Interface, Router
from bdrmapit_parser.parser.cyparser import TraceFile, OutputType, parse_parallel, build_graph_json, parse_sequential


def save_annotations(filename, bdrmapit: Bdrmapit, rupdates=None, iupdates=None, container: Container = None):
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
    # if container is not None:
    #     echos_cycles = (container.echos | container.cycles) - bdrmapit.graph.interfaces.keys()
    #     pb = Progress(len(echos_cycles), 'Adding echos and cycles', increment=1000000)
    #     for addr in pb.iterator(echos_cycles):
    #         asn = container.ip2as[addr]
    #         org = container.as2org[asn]
    #         row = {'addr': addr, 'router': addr, 'asn': asn, 'org': org, 'conn_asn': asn, 'conn_org': org, 'rtype': -1, 'itype': -1}
    #         values.append(row)
    con.executemany('insert into annotation (addr, router, asn, org, conn_asn, conn_org, rtype, itype) values (:addr, :router, :asn, :org, :conn_asn, :conn_org, :rtype, :itype)', values)
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
    parser.add_argument('--graph-only', action='store_true', help='Only create the graph, then save it to the specified file.')
    args = parser.parse_args()

    with open('schema.json') as f:
        schema = json.load(f)
    with open(args.config) as f:
        config = json.load(f)
    if not args.graph_only:
        schema['required'].extend(['as2org', 'as-rels'])
    validate(config, schema)

    ip2as = create_table(config['ip2as'])

    if 'graph' in config:
        with open(config['graph'], 'rb') as f:
            sys.stdout.write('Unpickling graph.')
            results = pickle.load(f)
            sys.stdout.write(' Done.\n')
    else:
        if 'warts' not in config and 'atlas' not in config:
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
        Progress.message('Files: {:,d}'.format(len(files)))

        if config['processes'] > 1:
            parseres = parse_parallel(files, ip2as, config['processes'])
        else:
            parseres = parse_sequential(files, ip2as)
        print('Serializing graph')
        results = build_graph_json(parseres, ip2as)
        if args.graph_only:
            with open(args.output, 'wb') as f:
                pickle.dump(results, f)
            return

    as2org = AS2Org(config['as2org']['as2org'], config['as2org'].get('additional'))
    bgp = BGP(config['as-rels']['rels'], config['as-rels']['cone'])

    nodes_file = config.get('aliases')
    prep = Container(ip2as, as2org, **results)
    graph = prep.construct(nodes_file=nodes_file)
    # graph = construct_graph(results['addrs'], results['nexthop'], results['multi'], results['dps'], results['mpls'], ip2as, as2org, nodes_file=nodes_file)

    bdrmapit = Bdrmapit(graph, as2org, bgp, strict=False)
    bdrmapit.set_dests()
    bdrmapit.annotate_lasthops()
    bdrmapit.graph_refinement(bdrmapit.routers_succ, bdrmapit.interfaces_pred, iterations=config['max_iterations'])

    save_annotations(args.output, bdrmapit)
    if args.nodes_as:
        save_node_as(args.nodes_as, bdrmapit)


if __name__ == '__main__':
    main()
