#!/usr/bin/env python
import json
import os
import sys
from argparse import ArgumentParser

from jsonschema import validate
from traceutils.as2org import AS2Org
from traceutils.bgp import BGP
from traceutils.progress import Progress
from traceutils.radix.ip2as import create_table

from algorithm.algorithm import Bdrmapit
from container.container import Container
import traceparser as tp
from output.saveres import Save
from traceparser import TraceFile, OutputType

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
        if 'warts' not in config and 'atlas' not in config and 'atlas-odd' not in config and 'jsonwarts' not in config:
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
        if 'jsonwarts' in config:
            jsonwarts = config['jsonwarts']
            if 'files' in jsonwarts:
                with open(jsonwarts['files']) as f:
                    files.extend(TraceFile(line.strip(), OutputType.JSONWARTS) for line in f)
            if 'files-list' in jsonwarts:
                files.extend(TraceFile(file, OutputType.JSONWARTS) for file in jsonwarts['files-list'])
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

    save = Save(args.output, bdrmapit, replace=True)
    save.save_annotations()
    save.save_ixps()
    if args.nodes_as:
        save.save_node_as(args.nodes_as)

if __name__ == '__main__':
    main()
