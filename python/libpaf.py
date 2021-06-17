# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Ericsson AB

#
# libpaf.py - A Python API to the Pathfinder client library.
#

import sys
import os
import socket
import collections
import enum
from ctypes import *

paf_c = CDLL("libpaf.so.0", use_errno=True)
lib_c = CDLL("libc.so.6", use_errno=True)

paf_value_is_int64_c = paf_c.paf_value_is_int64
paf_value_is_int64_c.restype = c_bool
paf_value_is_int64_c.argtypes = [c_int64]

paf_value_is_str_c = paf_c.paf_value_is_str
paf_value_is_str_c.restype = c_bool
paf_value_is_str_c.argtypes = [c_void_p]

paf_value_int64_c = paf_c.paf_value_int64
paf_value_int64_c.restype = c_int64
paf_value_int64_c.argtypes = [c_void_p]

paf_value_str_c = paf_c.paf_value_str
paf_value_str_c.restype = c_char_p
paf_value_str_c.argtypes = [c_void_p]

paf_props_create_c = paf_c.paf_props_create
paf_props_create_c.restype = c_void_p
paf_props_create_c.argtypes = None

paf_props_add_int64_c = paf_c.paf_props_add_int64
paf_props_add_int64_c.restype = c_void_p
paf_props_add_int64_c.argtypes = [c_void_p, c_char_p, c_int64]

paf_props_add_str_c = paf_c.paf_props_add_str
paf_props_add_str_c.restype = c_void_p
paf_props_add_str_c.argtypes = [c_void_p, c_char_p, c_char_p]

props_cb_type = CFUNCTYPE(None, c_char_p, c_void_p, c_void_p)

paf_props_foreach_c = paf_c.paf_props_foreach
paf_props_foreach_c.restype = None
paf_props_foreach_c.argtypes = [c_void_p, props_cb_type, c_void_p]

paf_props_destroy_c = paf_c.paf_props_destroy
paf_props_destroy_c.restype = None
paf_props_destroy_c.argtypes = [c_void_p]

def _props_p_to_c(p_props):
    c_props = paf_props_create_c()
    try:
        for key, values in p_props.items():
            for value in values:
                if isinstance(value, int):
                    paf_props_add_int64_c(c_props, key.encode('utf-8'), value)
                elif isinstance(value, str):
                    paf_props_add_str_c(c_props, key.encode('utf-8'),
                                    value.encode('utf-8'))
                else:
                    raise ValueError("invalid property value type: '%s'" % \
                                     typeof(value))
    except Exception as e:
        paf_props_destroy_c(c_props)
        raise e
    return c_props

def _props_c_to_p(c_props):
    p_props = collections.defaultdict(set)

    if c_props == None:
        return p_props

    def props_cb(c_name, c_value, user):
        p_name = c_name.decode('utf-8')
        if paf_value_is_int64_c(c_value):
            p_value = paf_value_int64_c(c_value)
        else:
            p_value = paf_value_str_c(c_value).decode('utf-8')
        p_props[p_name].add(p_value)
    c_props_cb = props_cb_type(props_cb)
    paf_props_foreach_c(c_props, c_props_cb, None)

    return p_props

class MatchType(enum.Enum):
    APPEARED = 0
    MODIFIED = 1
    DISAPPEARED = 2

paf_attach_c = paf_c.paf_attach
paf_attach_c.restype = c_void_p
paf_attach_c.argtypes = [c_char_p]

paf_publish_c = paf_c.paf_publish
paf_publish_c.restype = c_int64
paf_publish_c.argtypes = [c_void_p, c_void_p]

paf_modify_c = paf_c.paf_modify
paf_modify_c.restype = c_int
paf_modify_c.argtypes = [c_void_p, c_int64, c_void_p]

paf_set_ttl_c = paf_c.paf_set_ttl
paf_set_ttl_c.restype = None
paf_set_ttl_c.argtypes = [c_void_p, c_int64, c_int64]

paf_unpublish_c = paf_c.paf_unpublish
paf_unpublish_c.restype = c_int
paf_unpublish_c.argtypes = [c_void_p, c_int64]

subscribe_cb_type = CFUNCTYPE(None, c_int, c_int64, c_void_p, c_void_p)

paf_subscribe_c = paf_c.paf_subscribe
paf_subscribe_c.restype = c_int64
paf_subscribe_c.argtypes = [c_void_p, c_char_p, subscribe_cb_type, c_void_p]

paf_unsubscribe_c = paf_c.paf_unsubscribe
paf_unsubscribe_c.restype = None
paf_unsubscribe_c.argtypes = [c_void_p, c_int64]

paf_detach_c = paf_c.paf_detach
paf_detach_c.restype = None
paf_detach_c.argtypes = [c_void_p]

paf_close_c = paf_c.paf_close
paf_close_c.restype = None
paf_close_c.argtypes = [c_void_p]

paf_fd_c = paf_c.paf_fd
paf_fd_c.restype = c_int
paf_fd_c.argtypes = [c_void_p]

paf_process_c = paf_c.paf_process
paf_process_c.restype = c_int
paf_process_c.argtypes = [c_void_p]

paf_filter_escape_c = paf_c.paf_filter_escape
paf_filter_escape_c.restype = c_void_p
paf_filter_escape_c.argtypes = [c_char_p]

free_c = lib_c.free
free_c.restype = None
free_c.argtypes = [c_void_p]

def _assure_open(fun):
    def assure_open_wrap(self, *args, **kwargs):
        assert self.paf_context != None
        return fun(self, *args, **kwargs)
    return assure_open_wrap

def _assure_attached(fun):
    def assure_attached_wrap(self, *args, **kwargs):
        assert self.attached
        return fun(self, *args, **kwargs)
    return _assure_open(assure_attached_wrap)

class Context:
    def __init__(self, paf_context):
        self.paf_context = paf_context
        self.attached = True
        # Keep track of the callbacks, to avoid having them GCed
        self.subscriptions = {}
        self.publications = set()
    @_assure_attached
    def publish(self, props={}):
        try:
            c_props = _props_p_to_c(props)
            service_id = paf_publish_c(self.paf_context, c_props)
            if service_id < 0:
                raise Error('unable to publish service')
            self.publications.add(service_id)
            return service_id
        finally:
            paf_props_destroy_c(c_props)
    @_assure_attached
    def modify(self, service_id, props={}):
        if not service_id in self.publications:
            raise Error("unknown service id: %d" % service_id)
        try:
            c_props = _props_p_to_c(props)
            rc = paf_modify_c(self.paf_context, service_id, c_props)
            return rc
        finally:
            paf_props_destroy_c(c_props)
    @_assure_attached
    def set_ttl(self, service_id, new_ttl):
        if not service_id in self.publications:
            raise Error("unknown service id: %d" % service_id)
        if new_ttl < 0:
            raise Error("TTL must be non-negative integer")
        paf_set_ttl_c(self.paf_context, service_id, new_ttl)
    @_assure_attached
    def unpublish(self, service_id):
        if not service_id in self.publications:
            raise Error("unknown service id: %d" % service_id)
        paf_unpublish_c(self.paf_context, service_id)
        self.publications.remove(service_id)
    @_assure_attached
    def subscribe(self, subscribe_cb, filter=None):
        def proxy_cb(match_type, service_id, c_props, user):
            p_props = None
            if c_props != None:
                p_props = _props_c_to_p(c_props)
            subscribe_cb(MatchType(match_type), service_id, props = p_props)
        c_proxy_cb = subscribe_cb_type(proxy_cb)
        c_filter = None
        if filter != None:
            c_filter = filter.encode('utf-8')
        sub_id = paf_subscribe_c(self.paf_context, c_filter, c_proxy_cb, None)
        if sub_id < 0:
            raise Error('unable to add subscription')
        self.subscriptions[sub_id] = c_proxy_cb
        return sub_id
    def unsubscribe(self, sub_id):
        if not sub_id in self.subscriptions:
            raise Error("invalid subscription id: %d" % sub_id)
        paf_unsubscribe_c(self.paf_context, sub_id)
        del self.subscriptions[sub_id]
    @_assure_open
    def fd(self):
        return paf_fd_c(self.paf_context)
    @_assure_open
    def process(self):
        return paf_process_c(self.paf_context)
    @_assure_attached
    def detach(self):
        paf_detach_c(self.paf_context)
        self.attached = False
    @_assure_open
    def close(self):
        if self.paf_context != None:
            paf_close_c(self.paf_context)
            self.paf_context = None
    def __del__(self):
        if self.paf_context != None:
            self.close()

class Error(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)

def attach(domain):
    paf_context = paf_attach_c(domain.encode('utf-8'))
    assert paf_context != None
    return Context(paf_context)

def filter_escape(s):
    try:
        c_str = paf_filter_escape_c(s.encode('utf-8'))
        return cast(c_str, c_char_p).value.decode('utf-8')
    finally:
        free_c(c_str)
