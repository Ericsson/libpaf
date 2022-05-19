# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Ericsson AB

# The goal of this test suite is not to verify the library, but only
# to make sure the Python wrapper works properly.

import pytest
import os
import logging
import sys
import time
import subprocess
import select
import json
import random
import tempfile
import string
import collections

import libpaf
import paf.client

from logging.handlers import MemoryHandler

DEBUG = False

DOMAINS_DIR = 'pytest-domains.d'

DEBUG = False

def random_name():
    len = random.randint(1, 32)
    name = ""
    while len > 0:
        name += random.choice(string.ascii_lowercase)
        len -= 1
    return name

class Domain:
    def __init__(self):
        self.name = random_name()
        self.addr = "ux:%s" % random_name()
        self.server_process = None

        os.environ['PAF_DOMAINS'] = DOMAINS_DIR
        os.system("mkdir -p %s" % DOMAINS_DIR)

        self.file = "%s/%s" % (DOMAINS_DIR, self.name)
        with open(self.file, "w") as f:
            f.write(self.addr)
    def start_server(self):
        if self.server_process != None:
            return
        cmd = [ "pafd" ]
        if DEBUG:
            cmd.extend(["-l", "debug", "-s"])
        cmd.append(self.addr)

        self.server_process = subprocess.Popen(cmd)

        time.sleep(0.25)
    def stop_server(self):
        if self.server_process == None:
            return
        self.server_process.kill()
        self.server_process = None
        time.sleep(0.1)
    def __del__(self):
        self.stop_server()
        os.system("rm %s" % self.file)

@pytest.fixture(scope='function')
def domain():
    domain = Domain()

    domain.start_server()

    yield domain

    domain.stop_server()

def wait(contexts, timeout=None, until=None):
    deadline = None
    if timeout != None:
        deadline = time.time() + timeout

    fds = [context.fd() for context in contexts]

    while True:
        for context in contexts:
            context.process()
        if until is not None and until():
            break
        if deadline is not None and time.time() > deadline:
            break
        select_timeout = None
        if until is None and deadline is not None:
            select_timeout = deadline - time.time()
            if select_timeout < 0:
                select_timeout = 0
        elif until is not None:
            # periodically poll critera
            select_timeout = 0.1
        select.select(fds, [], [], select_timeout)

def test_publish_and_detach(domain):
    context = libpaf.attach(domain.name)
    props = { 'name': { 'service-x' }, 'key': { 'foo', 99 } }
    context.publish(props)

    conn = paf.client.connect(domain.addr)

    wait([context], until=lambda: len(conn.services()) == 1)

    context.detach()

    wait([context], until=lambda: len(conn.services()) == 0)

    context.close()

    assert len(conn.clients()) == 1

    conn.close()

class SubscriptionRecorder:
    def __init__(self):
        self.notifications = collections.defaultdict(dict)
    def __call__(self, match_type, service_id, props=None):
        self.notifications[match_type][service_id] = props

def test_subscribe_publish_modify_unpublish(domain):
    sub_context = libpaf.attach(domain.name)

    recorder = SubscriptionRecorder()
    sub_id = sub_context.subscribe(recorder)
    assert sub_id >= 0

    pub_context = libpaf.attach(domain.name)
    props = { 'name': { 'service-x' }, 'key': { 'foo', 99 } }
    service_id = pub_context.publish(props)

    wait([sub_context, pub_context],
         until=lambda: len(recorder.notifications) > 0)

    assert recorder.notifications[libpaf.MatchType.APPEARED][service_id] == props

    props['new_key'] = { 'new_value' }
    pub_context.modify(service_id, props)
    pub_context.set_ttl(service_id, 17)

    wait([sub_context, pub_context], timeout=0.25)

    assert recorder.notifications[libpaf.MatchType.MODIFIED][service_id] == props

    pub_context.unpublish(service_id)

    wait([sub_context, pub_context], timeout=0.25)

    assert service_id in recorder.notifications[libpaf.MatchType.DISAPPEARED]

def test_unsubscribe(domain):
    context = libpaf.attach(domain.name)

    recorder = SubscriptionRecorder()
    sub_id = context.subscribe(recorder)
    wait([context], timeout=0.25)

    context.unsubscribe(sub_id)

    context.publish()

    wait([context], timeout=0.25)

    assert len(recorder.notifications) == 0

def test_orphan(domain):
    context = libpaf.attach(domain.name)

    recorder = SubscriptionRecorder()
    sub_id = context.subscribe(recorder)

    conn = paf.client.connect(domain.addr)
    service_id = 4711
    generation = 10
    props = { 'name': { 'foo' } }
    ttl = 1
    conn.publish(service_id, generation, props, ttl)

    wait([context], timeout=0.25)
    assert len(recorder.notifications) == 1
    assert service_id in recorder.notifications[libpaf.MatchType.APPEARED]
    assert recorder.notifications[libpaf.MatchType.APPEARED][service_id] == \
        props

    conn.close()

    wait([context], timeout=0.25)
    assert len(recorder.notifications) == 1

    wait([context], timeout=ttl)
    assert len(recorder.notifications) == 2
    assert service_id in recorder.notifications[libpaf.MatchType.DISAPPEARED]
    assert recorder.notifications[libpaf.MatchType.DISAPPEARED][service_id] == \
        None

def test_subscribe_with_filter(domain):
    context = libpaf.attach(domain.name)

    recorder = SubscriptionRecorder()
    context.subscribe(recorder, filter='(name=service-x)')

    match_props = { 'name': { 'service-x' } }
    match_service_id = context.publish(match_props)
    
    non_match_props = { 'name': { 'service-y' } }
    non_match_service_id = context.publish(non_match_props)

    wait([context], timeout=0.25)

    assert match_service_id in \
        recorder.notifications[libpaf.MatchType.APPEARED]
    assert not non_match_service_id in \
        recorder.notifications[libpaf.MatchType.APPEARED]

MANY = 1000
def test_publish_unpublish_many(domain):
    context = libpaf.attach(domain.name)
    service_ids = []
    for num in range(0, MANY):
        props = { 'name': { "server-%d" % num } }
        service_id = context.publish(props)
        service_ids.append(service_id)
    recorder = SubscriptionRecorder()
    sub_id = context.subscribe(recorder)
    wait([context], timeout=1)

    for service_id in service_ids:
        assert service_id in recorder.notifications[libpaf.MatchType.APPEARED]

    for service_id in service_ids:
        context.unpublish(service_id)
    wait([context], timeout=1)

    for service_id in service_ids:
        assert service_id in recorder.notifications[libpaf.MatchType.DISAPPEARED]

def test_unpublish_unsynced(domain):
    domain.stop_server()

    context = libpaf.attach(domain.name)
    for num in range(0, MANY):
        service_id = context.publish()
        context.unpublish(service_id)

    wait([context], timeout=0.25)

    domain.start_server()

    wait([context], timeout=0.5)

    conn = paf.client.connect(domain.addr)
    assert len(conn.services()) == 0

    assert len(conn.clients()) == 2

    conn.close()

def test_filter_escape():
    assert libpaf.filter_escape('foo') == 'foo'
    assert libpaf.filter_escape('(foo') == '\\(foo'
