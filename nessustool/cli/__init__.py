"""
nessustool.cli

"""

__all__ = [
    'main'
]

import os
import nessusfile

from .arguments import arg_parser
from .logger import logger

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
    
    # format strings from the sorted records
    
    formatted_records = []

    for ip_address, fqdn, port in sorted(records):

        formatted_record = str(ip_address)

        if args.services:
            formatted_record = f'{formatted_record}:{port}'
        
        if fqdn is not None:
            formatted_record = f'{formatted_record} ({fqdn})'
        
        formatted_records.append(formatted_record)

    record_separator = ', ' if args.comma_separated else os.linesep
    print(record_separator.join(formatted_records))

command_handlers = {
    'list-hosts': list_hosts
}

def main():

    args = arg_parser.parse_args()

    try:
        command_handler = command_handlers[args.command]
    except KeyError:
        arg_parser.error(f"no handler registered for command '{args.command}'")
    
    command_handler(args)
