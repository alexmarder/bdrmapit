#!/usr/bin/env python
import json
import os
import sys
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from enum import Enum

from jsonschema import validate
from traceutils.as2org import AS2Org
from traceutils.bgp import BGP
from pb_amarder import Progress
from traceutils.radix.ip2as import create_table

from bdrmapit.algorithm.algorithm import Bdrmapit
from bdrmapit.container.container import Container
from bdrmapit.output.saveres import Save, ITDK
import scripts.traceparser as tp

from bdrmapit import __version__

class ExecTypes(Enum):
    traceparser = 1
    bdrmapit_all = 2
    bdrmapit_graph = 3
    bdrmapit_config = 4

def set_bdrmapit_parser(parser: ArgumentParser):
    group = parser.add_argument_group('CAIDA AS2Org')
    group.add_argument('-b', '--as2org', required=True, help='CAIDA AS2Org filename')
    group.add_argument('-B', '--as2org-extra', help='Filename with additional siblings')
    group = parser.add_argument_group('CAIDA AS Relationships')
    group.add_argument('-r', '--rels', required=True, help='The CAIDA relationship file that indicates provider or peer relationships.')
    group.add_argument('-c', '--cone', required=True, help='The CAIDA customer cone file.')
    group.add_argument('-P', '--peeringdb', help='PeeringDB json file (recommended).')
    parser.add_argument('-R', '--routers', help='Alias resolution file in CAIDA ITDK format.')
    parser.add_argument('-I', '--max-iterations', default=5, type=int, help='Maximum number of iterations to run the graph refinement loop.')
    parser.add_argument('-H', '--as-hints', help='AS hints file.')
    parser.add_argument('--no-echos', action='store_true', help='Ignore echo-only addresses.')
    set_bdrmapit_parser_output(parser)

def set_bdrmapit_parser_output(parser: ArgumentParser):
    group = parser.add_argument_group('Output')
    group.add_argument('-s', '--sqlite', help='Output filename for sqlite3 output.')
    group.add_argument('-k', '--itdk', help='Output in ITDK nodes.as format.')

def run_from_config(args):
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../schema.json')) as f:
        schema = json.load(f)
    with open(args.config) as f:
        config = json.load(f)
    if not args.graph_only:
        schema['required'].extend(['as2org', 'as-rels'])
    validate(config, schema)
    args.ip2as = config['ip2as']
    if 'graph' in config:
        args.etype = ExecTypes.bdrmapit_graph
        args.graph = config['graph']
    else:
        args.wfiles = config['warts'].get('files') if 'warts' in config else None
        args.wfilelist = config['warts'].get('files-list') if 'warts' in config else None
        args.afiles = config['atlas'].get('files') if 'atlas' in config else None
        args.afilelist = config['atlas'].get('files-list') if 'atlas' in config else None
        args.wfiles = config['jsonwarts'].get('files') if 'jsonwarts' in config else None
        args.wfilelist = config['jsonwarts'].get('files-list') if 'jsonwarts' in config else None
        args.processes = config['processes']
        if args.graph_only:
            args.output = args.graph_only
            args.etype = ExecTypes.traceparser
        else:
            args.etype = ExecTypes.bdrmapit_all
    if args.etype != ExecTypes.traceparser:
        args.as2org = config['as2org']['as2org']
        args.as2org_extra = config['as2org'].get('additional')
        args.rels = config['as-rels']['rels']
        args.cone = config['as-rels']['cone']
        args.max_iterations = config['max_iterations']
        args.routers = config.get('aliases')
        args.as_hints = config.get('hints')
        args.peeringdb = config.get('peeringdb')

def main(args=None):
    if args is None:
        parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
        subs = parser.add_subparsers()

        tparser = subs.add_parser('parser')
        tp.set_parser(tparser, output=True)
        tparser.set_defaults(etype=ExecTypes.traceparser)

        bparser = subs.add_parser('all')
        tp.set_parser(bparser, group='Traceroute Parsing', output=False)
        set_bdrmapit_parser(bparser)
        bparser.set_defaults(etype=ExecTypes.bdrmapit_all)

        gparser = subs.add_parser('graph')
        gparser.add_argument('-g', '--graph', required=True, help='Pickle file with graph.')
        gparser.add_argument('-i', '--ip2as', required=True, help='Filename of prefix-to-AS mappings in CAIDA prefix2as format.')
        set_bdrmapit_parser(gparser)
        gparser.set_defaults(etype=ExecTypes.bdrmapit_graph)

        cparser = subs.add_parser('json')
        cparser.add_argument('-c', '--config', required=True, help='JSON config file.')
        cparser.add_argument('--graph-only', help='Only create the graph, then save it to the specified file.')
        set_bdrmapit_parser_output(cparser)
        cparser.set_defaults(etype=ExecTypes.bdrmapit_config)

        parser.add_argument('--version', action='version', version='%(prog)s {version}'.format(version=__version__))

        args = parser.parse_args()

    if args.etype != ExecTypes.traceparser:
        if not (args.sqlite or args.itdk):
            print('Must specify output filename', file=sys.stderr)
            sys.exit(1)

    if args.etype == ExecTypes.bdrmapit_config:
        run_from_config(args)
        return main(args=args)

    if args.etype == ExecTypes.traceparser:
        tp.main(args=args)
        return

    ip2as = create_table(args.ip2as)
    as2org = AS2Org(args.as2org, additional=args.as2org_extra)
    if args.etype == ExecTypes.bdrmapit_all:
        args.output = None
        parseres = tp.main(args=args, ip2as=ip2as)
        prep = Container(ip2as, as2org, parseres)
    else:
        sys.stdout.write('Unpickling graph.')
        prep = Container.load(ip2as, as2org, args.graph)
        sys.stdout.write(' Done.\n')

    bgp = BGP(args.rels, args.cone)
    use_hints = args.as_hints is not None

    graph = prep.construct(nodes_file=args.routers, hints_file=args.as_hints, no_echos=args.no_echos)

    bdrmapit = Bdrmapit(graph, as2org, bgp, strict=False)
    if args.peeringdb:
        bdrmapit.peeringdb_ixpasns(args.peeringdb, ip2as)
    bdrmapit.set_dests()
    bdrmapit.annotate_lasthops(usehints=use_hints, use_provider=True)
    bdrmapit.graph_refinement(bdrmapit.routers_succ, bdrmapit.interfaces_pred, iterations=args.max_iterations, usehints=use_hints, use_provider=True)

    if args.sqlite:
        save = Save(args.sqlite, bdrmapit, replace=True)
        save.save_annotations()
        save.save_ixps()
        save.save_links()
    if args.itdk:
        include_all = args.routers is None
        save = ITDK(bdrmapit)
        save.write_nodes(args.itdk, include_all=include_all)

if __name__ == '__main__':
    main()
