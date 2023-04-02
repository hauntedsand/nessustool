"""
nessustool.arguments

"""

__all__ = [
    'arg_parser'
]

import argparse

def configure_list_hosts_parser(parser):

    parser.add_argument('-f', '--format', choices=['comma-list', 'csv', 'json', 'lines', 'table'], default='lines')
    parser.add_argument('-H', '--with-hostnames', action='store_true')
    parser.add_argument('-p', '--plugins', type=int, nargs='*', default=[])
    parser.add_argument('-s', '--services', action='store_true')
    parser.add_argument('nessus_scan')

def configure_root_parser(parser):

    parser.add_argument('-d', '--debug', action='store_true')
    subparsers = parser.add_subparsers(dest='command')
    subparsers.required = True
    configure_list_hosts_parser(subparsers.add_parser('list-hosts'))

def build_arg_parser():

    parser = argparse.ArgumentParser(prog='nessustool')
    configure_root_parser(parser)
    return parser

arg_parser = build_arg_parser()
