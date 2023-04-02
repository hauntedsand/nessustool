"""
nessustool.cli

"""

__all__ = [
    'main'
]

import collections
import csv
import json
import os
import nessusfile
import sys
import tabulate

from .arguments import arg_parser
from .logger import logger

Issue = collections.namedtuple('Issue', ['host', 'report_item'])

def list_hosts(args):

    scan = nessusfile.NessusScanFile.load(args.nessus_scan)

    records = set()

    for host in scan.hosts:
        for report_item in host.report_items:
            if len(args.plugins) == 0 or report_item.plugin_id in args.plugins:
                records.add((host.ip_address, host.fqdn, report_item.port))
    
    # filter out unwanted information and de-duplicate
    
    if not args.services:
        records = set(((ip_address, fqdn, None)
            for ip_address, fqdn, _ in records))
    
    if not args.with_hostnames:
        records = set(((ip_address, None, port)
            for ip_address, _, port in records))
    
    records = sorted(records)

    if args.format == 'csv':
        csv_writer = csv.writer(sys.stdout)
        csv_writer.writerows(records)
    
    elif args.format in ('comma-list', 'lines'):
        formatted_records = []

        for ip_address, fqdn, port in records:

            formatted_record = str(ip_address)

            if args.services:
                formatted_record = f'{formatted_record}:{port}'
            
            if fqdn is not None:
                formatted_record = f'{formatted_record} ({fqdn})'
            
            formatted_records.append(formatted_record)

        record_separator = ', ' if args.format == 'comma-list' else os.linesep
        print(record_separator.join(formatted_records))
    
    elif args.format == 'json':
        obj = []

        for ip_address, fqdn, port in records:
            obj.append({
                'ip_address': str(ip_address),
                'fqdn': fqdn,
                'port': port
            })
        
        print(json.dumps(obj))
    
    elif args.format == 'table':
        formatted_rows = []

        for ip_address, fqdn, port in records:
            row = [str(ip_address)]
            
            if args.services:
                row.append('--' if port == 0 else str(port))
            
            if args.with_hostnames:
                row.append(('--' if fqdn is None else fqdn))
            
            formatted_rows.append(tuple(row))
        
        print(tabulate.tabulate(formatted_rows, tablefmt='plain'))

field_selectors = {
    'fqdn':        lambda issue: issue.host.fqdn,
    'ip':          lambda issue: issue.host.ip_address,
    'output':      lambda issue: issue.report_item.plugin_output,
    'plugin':      lambda issue: issue.report_item.plugin_id,
    'plugin-name': lambda issue: issue.report_item.plugin_name,
    'port':        lambda issue: issue.report_item.port
}

def select_fields(args):

    scan = nessusfile.NessusScanFile.load(args.nessus_scan)

    records = set()

    for host in scan.hosts:
        for report_item in host.report_items:
            if len(args.plugins) == 0 or report_item.plugin_id in args.plugins:

                record, issue = [], Issue(host, report_item)
                
                for field_name in args.fields:
                    try:
                        field_selector = field_selectors[field_name]
                    except KeyError:
                        logger.error(f"unrecognised field '{field_name}'")
                    
                    record.append(field_selector(issue))
                
                records.add(tuple(record))
    
    csv_writer = csv.writer(sys.stdout)
    csv_writer.writerows(sorted(records))

command_handlers = {
    'list-hosts': list_hosts,
    'select-fields': select_fields
}

def main():

    args = arg_parser.parse_args()

    try:
        command_handler = command_handlers[args.command]
    except KeyError:
        arg_parser.error(f"no handler registered for command '{args.command}'")
    
    command_handler(args)
