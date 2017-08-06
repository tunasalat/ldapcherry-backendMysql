#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
from __future__ import unicode_literals

import pytest
import sys, hashlib
from sets import Set
from ldapcherry.backend.backendMysql import Backend
from ldapcherry.exceptions import *
import cherrypy
import logging
import copy


cfg = {
    'display_name': 'test',
    'user_attributes': 'grp1, grp2',
    'backend_user': 'ssoadm',
    'backend_password': '',
    'backend_host': 'localhost',
    'backend_db': 'sso_test',
}

def syslog_error(msg='', context='',
        severity=logging.INFO, traceback=False):
    pass

cherrypy.log.error = syslog_error
attr = ['id', 'user', 'password', 'name', 'mail', 'groups']

pineapple = {
'user':  'pineapple',
'password': 'strongpassword',
'name':  'pineapple_name',
'mail': 'pineapple@test.org'
}

maple_leaf = {
'user':  'maple_leaf',
'password': 'bestpassword',
'name':  'maple_leaf_name',
'mail': 'maple_leaf@test.org'
}

sicle = {
'user': u'sicle☭',
'password': 'hammer',
'name': u'sicle_name',
'mail': 'sicle@test.org'
}

default_groups = ['grp1', 'grp2', 'grp3']
initial_groups1 = ['grp4', 'grp5']
initial_groups2 = ['grp2', 'grp4']


class TestError(object):

    def testNominal(self):
        inv = Backend(cfg, cherrypy.log, 'test', attr, 'user')
        return True

    def testPasswordHashed(self):
        inv = Backend(cfg, cherrypy.log, 'test', attr, 'user')
        pineapple = {
        'user':  'pineapple',
        'password': 'strongpassword',
        'name':  'pineapple_name',
        'mail': 'pineapple@test.org'
        }
        try:
            inv.del_user('pineapple')
        except:
            pass
        inv.add_user(pineapple)
        ret = inv.get_user('pineapple')['password']
        inv.del_user('pineapple')
        assert ret == hashlib.sha1('strongpassword').hexdigest()

    def testAuthSuccess(self):
        inv = Backend(cfg, cherrypy.log, 'test', attr, 'user')
        pineapple = {
        'user':  'pineapple',
        'password': 'strongpassword',
        'name':  'pineapple_name',
        'mail': 'pineapple@test.org'
        }
        try:
            inv.del_user('pineapple')
        except:
            pass
        inv.add_user(pineapple)
        ret = inv.auth('pineapple', 'strongpassword')
        inv.del_user('pineapple')
        assert ret == True

    def testAuthFailure(self):
        inv = Backend(cfg, cherrypy.log, 'test', attr, 'user')
        pineapple = {
        'user':  'pineapple',
        'password': 'strongpassword',
        'name':  'pineapple_name',
        'mail': 'pineapple@test.org'
        }
        try:
            inv.del_user('pineapple')
        except:
            pass
        inv.add_user(pineapple)
        res = inv.auth('notauser', 'password') and inv.auth('pineapple', 'notapassword')
        inv.del_user('pineapple')
        assert res == False

    def testGetUser(self):
        inv = Backend(cfg, cherrypy.log, 'test', attr, 'user')
        try:
            inv.del_user('pineapple')
        except:
            pass
        inv.add_user(pineapple)
        inv.add_to_groups('pineapple', default_groups)

        ret = inv.get_user('pineapple')
        ret.pop('id')

        expected = pineapple
        expected.update({'groups': 'grp1,grp2,grp3'})
        inv.del_user('pineapple')
        assert ret == expected

    def testGetGroups(self):
        inv = Backend(cfg, cherrypy.log, 'test', attr, 'user')
        try:
            inv.del_user('pineapple')
        except:
            pass
        inv.add_user(pineapple)
        inv.add_to_groups('pineapple', default_groups)
        ret = inv.get_groups('pineapple')
        expected = default_groups
        inv.del_user('pineapple')
        assert ret == expected

    def testGetGroupsNotIntersected(self):
        inv = Backend(cfg, cherrypy.log, 'test', attr, 'user')
        try:
            inv.del_user('pineapple')
        except:
            pass
        inv.add_user(pineapple)
        inv.add_to_groups('pineapple', initial_groups1)
        inv.add_to_groups('pineapple', default_groups)
        ret = inv.get_groups('pineapple')
        expected = default_groups + initial_groups1
        inv.del_user('pineapple')
        assert ret == expected

    def testGetGroupsIntersected(self):
        inv = Backend(cfg, cherrypy.log, 'test', attr, 'user')
        try:
            inv.del_user('pineapple')
        except:
            pass
        inv.add_user(pineapple)
        inv.add_to_groups('pineapple', initial_groups2)
        inv.add_to_groups('pineapple', default_groups)
        ret = inv.get_groups('pineapple')
        expected = default_groups + ['grp4']
        inv.del_user('pineapple')
        assert ret == expected

    def testGetGroupsAlreadyPresent(self):
        inv = Backend(cfg, cherrypy.log, 'test', attr, 'user')
        try:
            inv.del_user('pineapple')
        except:
            pass
        inv.add_user(pineapple)
        inv.add_to_groups('pineapple', default_groups)
        inv.add_to_groups('pineapple', default_groups)
        ret = inv.get_groups('pineapple')
        expected = default_groups
        inv.del_user('pineapple')
        assert ret == expected

    def testSearchUser(self):
        inv = Backend(cfg, cherrypy.log, 'test', attr, 'user')
        try:
            inv.del_user('pineapple')
            inv.del_user('maple_leaf')
            inv.del_user('sicle☭')
        except:
            pass
        inv.add_user(pineapple)
        inv.add_user(maple_leaf)
        inv.add_user(sicle)
        ret = inv.search('ple')
        expected = ['pineapple', 'maple_leaf']
        inv.del_user('pineapple')
        inv.del_user('maple_leaf')
        inv.del_user('sicle☭')
        assert Set(ret.keys()) == Set(expected)

    def testAddUser(self):
        inv = Backend(cfg, cherrypy.log, 'test', attr, 'user')
        try:
            inv.del_user('pineapple')
        except:
            pass
        inv.add_user(pineapple)
        inv.del_user('pineapple')

    def testModifyUser(self):
        inv = Backend(cfg, cherrypy.log, 'test', attr, 'user')
        try:
            inv.del_user('pineapple')
            inv.del_user('mango')
        except:
            pass
        pineapple = {
        'user':  'pineapple',
        'password': 'strongpassword',
        'name':  'pineapple_name',
        'mail': 'pineapple@test.org'
        }
        expected = copy.deepcopy(pineapple)
        expected['mail'] = 'mango@mail.org'
        expected['user'] = 'mango'
        expected['groups'] = None
        expected['password'] = hashlib.sha1('strongpassword').hexdigest()
        inv.add_user(pineapple)
        inv.set_attrs('pineapple', {'mail': 'mango@mail.org', 'user': 'mango'})
        ret = inv.get_user('mango')
        ret.pop('id')
        inv.del_user('mango')
        assert ret == expected

    def testModifyUserPassword(self):
        inv = Backend(cfg, cherrypy.log, 'test', attr, 'user')
        try:
            inv.del_user('pineapple')
        except:
            pass
        pineapple = {
        'user':  'pineapple',
        'password': 'strongpassword',
        'name':  'pineapple_name',
        'mail': 'pineapple@test.org'
        }
        expected = copy.deepcopy(pineapple)
        expected['password'] = hashlib.sha1('verystrongpassword').hexdigest()
        expected['groups'] = None
        inv.add_user(pineapple)
        inv.set_attrs('pineapple', {'password': 'verystrongpassword'})
        ret = inv.get_user('pineapple')
        ret.pop('id')
        inv.del_user('pineapple')
        assert ret == expected

    def testAddUserDuplicate(self):
        inv = Backend(cfg, cherrypy.log, 'test', attr, 'user')
        try:
            inv.add_user(pineapple)
            inv.add_user(pineapple)
        except UserAlreadyExists:
            inv.del_user('pineapple')
            return
        else:
            inv.del_user('pineapple')
            raise AssertionError("expected an exception")

    def testDelUserDontExists(self):
        inv = Backend(cfg, cherrypy.log, 'test', attr, 'user')
        try:
            inv.del_user('pineapple')
        except:
            pass

        inv.add_user(pineapple)

        try:
            inv.del_user('pineapple')
            inv.del_user('pineapple')
        except UserDoesntExist:
            return
        else:
            inv.del_user('pineapple')
            raise AssertionError("expected an exception")
