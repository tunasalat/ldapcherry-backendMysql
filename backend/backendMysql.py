# -*- coding: utf-8 -*-
# vim:set expandtab tabstop=4 shiftwidth=4:
#
# The MIT License (MIT)
# LdapCherry
# Copyright (c) 2014 Carpentier Pierre-Francois

# This is a demo backend

from sets import Set
import mysql.connector
import ldapcherry.backend
from ldapcherry.exceptions import UserDoesntExist, \
    GroupDoesntExist, MissingParameter, \
    UserAlreadyExists
import re


class Backend(ldapcherry.backend.Backend):

    def __init__(self, config, logger, name, attrslist, key):
        """ Initialize the backend

        :param config: the configuration of the backend
        :type config: dict {'config key': 'value'}
        :param logger: the cherrypy error logger object
        :type logger: python logger
        :param name: id of the backend
        :type name: string
        :param attrslist: list of the backend attributes
        :type attrslist: list of strings
        :param key: the key attribute
        :type key: string
        """
        self.config = config
        self._logger = logger
        self.backend_name = name
        self.user_attributes = self.get_param('user_attributes')
        self.backend_user = self.get_param('backend_user')
        self.backend_password = self.get_param('backend_password')
        self.backend_uri = self.get_param('backend_uri')
        self.backend_db = self.get_param('backend_db')
        self.key = key

    def _connect(self):
        """Connect to the mysql server"""
        try:
            mysql_client = mysql.connector.connect(user=self.backend_user, password=self.backend_password,
                              host=self.uri, database=self.db)
        except Exception as e:
            mysql_client.close()
            #self._exception_handler(e)
        return mysql_client

    def auth(self, username, password):
        """ Check authentication against the backend

        :param username: 'key' attribute of the user
        :type username: string
        :param password: password of the user
        :type password: string
        :rtype: boolean (True is authentication success, False otherwise)
        """
        mysql_client = self._connect()
        cursor = mysql_client.cursor()
        query = ("SELECT password  FROM auth WHERE user = %s")

        cursor.execute(query, [ username ])
        result = cursor.fetchall()

        if result[0][0] == password:
            cursor.close()
            mysql_client.close()
            return True
        return False

    #def attrs_pretreatment(self, attrs):
    #    attrs_keys = []
    #    attrs_values = []
    #    for a in attrs:
    #        attrs_keys.append(str(a))
    #        attrs_values.append(str(attrs[a]))
    #    return attrs_keys, attrs_values

    def add_user(self, attrs):
        """ Add a user to the backend

        :param attrs: attributes of the user
        :type attrs: dict ({<attr>: <value>})

        .. warning:: raise UserAlreadyExists if user already exists
        """
        mysql_client = self._connect()
        cursor = mysql_client.cursor()
        username = attrs[self.key]
        query = ("SELECT id  FROM auth WHERE user = %s")
        cursor.execute(query, [ username ])
        result = cursor.fetchall()

        if result != []:
            cursor.close()
            mysql_client.close()
            raise UserAlreadyExists(attrs[self.key], self.backend_name)
            return False

        #attrs_keys, attrs_values = self.attrs_pretreatment(attrs)
        #attrs_keys.append('user')
        #attrs_values.append(username)

        placeholders = ', '.join(['%s'] * len(attrs))
        columns = ', '.join(attrs.keys())
        sql = "INSERT INTO users ( %s ) VALUES ( %s )" % (columns, placeholders)
        cursor.execute(query, attrs.values())
        mysql_client.commit()
        cursor.close()
        mysql_client.close()

    def del_user(self, username):
        """ Delete a user from the backend

        :param username: 'key' attribute of the user
        :type username: string

        """
        mysql_client = self._connect()
        cursor = mysql_client.cursor()
        try:
            query = ("DELETE FROM users WHERE user = %s")
            cursor.execute(query, [ username ])
            mysql_client.commit()
            cursor.close()
            mysql_client.close()
        except:
            raise UserDoesntExist(username, self.backend_name)

    def set_attrs(self, username, attrs):
        """ Set a list of attributes for a given user

        :param username: 'key' attribute of the user
        :type username: string
        :param attrs: attributes of the user
        :type attrs: dict ({<attr>: <value>})
        """
        mysql_client = self._connect()
        cursor = mysql_client.cursor()
        query = 'UPDATE users SET {}'.format(', '.join('{}=%s'.format(k) for k in attrs))
        cursor.execute(query, attrs.values())
        mysql_client.commit()
        cursor.close()
        mysql_client.close()

    def add_to_groups(self, username, groups):
        """ Add a user to a list of groups

        :param username: 'key' attribute of the user
        :type username: string
        :param groups: list of groups
        :type groups: list of strings
        """

        mysql_client = self._connect()
        cursor = mysql_client.cursor()
        query = 'SELECT groups FROM users WHERE user = %s'
        cursor.execute(query, [ username ])
        groups =  cursor.fetchall()[0][0].split(",")
        for item in groups:
            if item not in groups:
                groups.append(item)

        new_groups = ','.join(map(str, groups)) 
        query = 'UPDATE users SET groups = %s WHERE user = %s'
        cursor.execute(query, [ new_groups, username ])
        mysql_client.commit()
        cursor.close()
        mysql_client.close()

    def del_from_groups(self, username, groups):
        """ Delete a user from a list of groups

        :param username: 'key' attribute of the user
        :type username: string
        :param groups: list of groups
        :type groups: list of strings

        .. warning:: raise GroupDoesntExist if group doesn't exist
        """
        mysql_client = self._connect()
        cursor = mysql_client.cursor()

        query = 'SELECT groups FROM users WHERE user = %s'
        cursor.execute(query, [ username ])
        groups =  cursor.fetchall()[0][0].split(",")
        for item in groups:
            if item in groups:
                groups.remove(item)

        new_groups = ','.join(map(str, groups)) 
        query = 'UPDATE users SET groups = %s WHERE user = %s'
        cursor.execute(query, [ new_groups, username ])
        mysql_client.commit()
        cursor.close()
        mysql_client.close()

    def search(self, searchstring):
        """ Search backend for users

        :param searchstring: the search string
        :type searchstring: string
        :rtype: dict of dict ( {<user attr key>: {<attr>: <value>}} )
        """
        mysql_client = self._connect()
        cursor = mysql_client.cursor()
        ret = {}
        query = 'SELECT * FROM user WHERE user RLIKE "%s" or mail RLIKE "%s"'
        cursor.execute(query, [ searchstring, searchstring])

        result = cursor.fetchall()
        cols = cursor.column_names

        ret = {}
        for i in xrange(len(result)):
            ret[result[i][cols.index('user')]] = dict(zip(cols, result[i]))

        cursor.close()
        mysql_client.close()

        return ret

    def get_user(self, username):
        """ Get a user's attributes

        :param username: 'key' attribute of the user
        :type username: string
        :rtype: dict ( {<attr>: <value>} )

        .. warning:: raise UserDoesntExist if user doesn't exist
        """
        mysql_client = self._connect()
        cursor = mysql_client.cursor()
        query = 'SELECT * FROM user WHERE user = "%s"'

        cursor.execute(query, [ username ])
        result = cursor.fetchall()
        cols = cursor.column_names

        ret = {}

        ret = dict(zip(cols, result[i]))

        cursor.close()
        mysql_client.close()

        return ret

        #try:
        #    return self.users[username]
        #except:
        #    raise UserDoesntExist(username, self.backend_name)

    def get_groups(self, username):
        """ Get a user's groups

        :param username: 'key' attribute of the user
        :type username: string
        :rtype: list of groups
        """

        mysql_client = self._connect()
        cursor = mysql_client.cursor()
        query = 'SELECT groups FROM user WHERE user = "%s"'

        cursor.execute(query, [ username ])
        groups =  cursor.fetchall()[0][0].split(",")

        cursor.close()
        mysql_client.close()

        return groups


        #try:
        #    return self.users[username]['groups']
        #except:
        #    raise UserDoesntExist(username, self.backend_name)
