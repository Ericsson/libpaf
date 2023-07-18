#!/usr/bin/python3

# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Ericsson AB

import sys
import collections
import select
import time

import paf.client as client

NUM_RETRIES=100
RETRY_INTERVAL=0.01

def usage(name):
    print("%s <addr> <cmd> [<arg>...]" % name)
    print("Commands:")
    print("    assure-up")
    print("    assure-client-from <remote-addr>")
    print("    assure-client-count <count>")
    print("    assure-service <service-id> [<prop-name> <prop-value> ...]")
    print("    assure-service-count <count>")
    print("    assure-subscription <subscription-id> <filter>")

if len(sys.argv) < 3 or sys.argv[1] == '-h':
    usage(sys.argv[0])
    sys.exit(1)

def assure_up(conn, *args):
    conn.ping()
    sys.exit(0)

def assure_client_from(conn, *args):
    remote_addr = args[0]

    clients = conn.clients()

    for client in clients:
        if remote_addr == client[1]:
            sys.exit(0)
    sys.exit(1)

def assure_client_count(conn, *args):
    expected_count = int(args[0])

    # tclient should not be included in count
    num_clients = len(conn.clients()) - 1

    if expected_count == num_clients:
        sys.exit(0)
    else:
        sys.exit(1)

def parse_props(args):
    if len(args) % 2 != 0:
        raise ValueError("Service properties must be key-value pairs")
    service_props = collections.defaultdict(set)
    for i in range(0, len(args), 2):
        value_str = args[i+1]
        try:
            service_props[args[i]].add(int(value_str))
        except ValueError:
            service_props[args[i]].add(value_str)
    return service_props

def assure_service(conn, *args):
    if args[0] == 'any':
        needle_id = None
    else:
        needle_id = int(args[0], 16)
    needle_props = parse_props(args[1:])
    services = conn.services()
    for service in services:
        service_id = service[0]
        generation = service[1]
        props = service[2]
        ttl = service[3]
        owner = service[4]
        is_orphan = (len(service) == 6 and 'orphan_since' in service[5])
        if (needle_id == None or service_id == needle_id) \
           and props == needle_props and not is_orphan:
            sys.exit(0)
    sys.exit(1)

def assure_service_count(conn, *args):
    expected_count = int(args[0])
    services = conn.services()
    if len(services) == expected_count:
        sys.exit(0)
    else:
        sys.exit(1)

def assure_subscription(conn, *args):
    needle_sub_id = int(args[0], 16)
    needle_filter = args[1]
    subscriptions = conn.subscriptions()
    for subscription in subscriptions:
        sub_id, client_ref, optargs = subscription
        filter = optargs.get('filter')
        if sub_id == needle_sub_id and \
           filter == needle_filter:
            sys.exit(0)
    sys.exit(1)

addr = sys.argv[1]

conn = None
for i in range(0, NUM_RETRIES):
    try:
        conn = client.connect(addr)
        break;
    except client.Error:
        time.sleep(RETRY_INTERVAL)

if conn == None:
    print("Unable to connect to server at %s. Giving up." % addr)
    sys.exit(1)

cmd = sys.argv[2]

fun = None
if cmd == 'assure-up':
    fun = assure_up
elif cmd == 'assure-client-from':
    fun = assure_client_from
elif cmd == 'assure-client-count':
    fun = assure_client_count
elif cmd == 'assure-service':
    fun = assure_service
elif cmd == 'assure-service-count':
    fun = assure_service_count
elif cmd == 'assure-subscription':
    fun = assure_subscription
else:
    print("Unknown command \"%s\"." % cmd)
    sys.exit(1)

fun(conn, *sys.argv[3:])
