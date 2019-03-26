# -*- coding: utf-8; -*-
#
# This file is part of Superdesk.
#
# Copyright 2013, 2014 Sourcefabric z.u. and contributors.
#
# For the full copyright and license information, please see the
# AUTHORS and LICENSE files distributed with this source code, or
# at https://www.sourcefabric.org/superdesk/license

import logging
from base64 import b64encode
from distutils.util import strtobool
from flask import current_app as app

import superdesk
from superdesk.utils import get_hash, is_hashed
from superdesk.users.errors import UserNotRegisteredException
from superdesk.emails import send_activate_account_email
from superdesk.roles.errors import RoleDoesNotExist


logger = logging.getLogger(__name__)


class CreateUserCommand(superdesk.Command):
    """Create a user with given username, password and email.

    If user with given username exists, reset password.
    """

    option_list = (
        superdesk.Option('--username', '-u', dest='username', required=True),
        superdesk.Option('--password', '-p', dest='password', required=True),
        superdesk.Option('--email', '-e', dest='email', required=True),
        superdesk.Option('--admin', '-a', dest='admin', required=False, action='store_true'),
        superdesk.Option('--support', '-s', dest='support', required=False, action='store_true'),
    )

    def run(self, username, password, email, admin=False, support=False):

        # force type conversion to boolean
        user_type = 'administrator' if admin else 'user'

        userdata = {
            'username': username,
            'password': password,
            'email': email,
            'user_type': user_type,
            'is_active': admin,
            'is_support': support,
            'needs_activation': not admin
        }

        with app.test_request_context('/users', method='POST'):
            if userdata.get('password', None) and not is_hashed(userdata.get('password')):
                userdata['password'] = get_hash(userdata.get('password'),
                                                app.config.get('BCRYPT_GENSALT_WORK_FACTOR', 12))

            user = superdesk.get_resource_service('users').find_one(username=userdata.get('username'), req=None)

            if user:
                logger.info('user already exists %s' % (userdata))
            else:
                logger.info('creating user %s' % (userdata))
                superdesk.get_resource_service('users').post([userdata])
                logger.info('user saved %s' % (userdata))

            return userdata


class ManageUserCommand(superdesk.Command):
    """Manage an already created user with given username.

    It allows to modify certain attributes from the user model
    """

    option_list = (
        superdesk.Option('--username', '-u', dest='username', required=True),
        superdesk.Option('--admin', '-a', dest='admin', required=False,
            help='If true it will turn the user into admin type'),
        superdesk.Option('--support', '-s', dest='support', required=False,
            help='If true it will turn the user into support one'),
        superdesk.Option('--active', '-atv', dest='active', required=False),
        superdesk.Option('--enabled', '-e', dest='enabled', required=False),
        superdesk.Option('--role', '-r', dest='role', type=str),
        superdesk.Option('--firstname', '-fn', dest='firstname', type=str),
        superdesk.Option('--lastname', '-ln', dest='lastname', type=str)
    )

    def run(self, username, **kwargs):

        def _bool(param):
            return bool(strtobool(param))

        updates = {}

        admin = kwargs.get('admin')
        is_support = kwargs.get('support')
        is_active = kwargs.get('active')
        is_enabled = kwargs.get('enabled')
        role_param = kwargs.get('role')
        first_name = kwargs.get('firstname')
        last_name = kwargs.get('lastname')

        if admin:
            updates['user_type'] = 'administrator' if admin else 'user'

        if is_support:
            updates['is_support'] = _bool(is_support)

        if is_active:
            updates['is_active'] = _bool(is_active)

        if is_enabled:
            updates['is_enabled'] = _bool(is_enabled)

        if first_name:
            updates['first_name'] = first_name

        if last_name:
            updates['last_name'] = last_name

        with app.test_request_context('/users', method='POST'):
            if role_param:
                role = superdesk.get_resource_service('roles').find_one(name=role_param, req=None)

                if role is None:
                    raise RoleDoesNotExist('The desired role `%s` does not exist' % role_param)

                updates['role'] = role['_id']

            users = superdesk.get_resource_service('users')
            user = users.find_one(username=username, req=None)

            if user is None:
                raise UserNotRegisteredException('User `%s` not found' % username)

            updates['display_name'] = '{0} {1}'.format(
                first_name or user.get('first_name', ''),
                last_name or user.get('last_name', ''))

            logger.info('updating user %s' % (updates))
            users.system_update(user['_id'], updates, user)
            logger.info('user updated %s' % (updates))

            return updates


class HashUserPasswordsCommand(superdesk.Command):
    """Hash all the user passwords which are not hashed yet.

    """

    def run(self):
        users = superdesk.get_resource_service('auth_users').get(req=None, lookup={})
        for user in users:
            pwd = user.get('password')
            if not is_hashed(pwd):
                updates = {}
                hashed = get_hash(user['password'], app.config.get('BCRYPT_GENSALT_WORK_FACTOR', 12))
                user_id = user.get('_id')
                updates['password'] = hashed
                superdesk.get_resource_service('users').patch(user_id, updates=updates)


class GetAuthTokenCommand(superdesk.Command):
    """Gets auth token.

    Generate an authorization token to be able to authenticate against the REST api without
    starting the client the copy the authorization header.
    """

    option_list = (
        superdesk.Option('--username', '-u', dest='username', required=True),
        superdesk.Option('--password', '-p', dest='password', required=True)
    )

    def run(self, username, password):
        credentials = {
            'username': username,
            'password': password
        }
        service = superdesk.get_resource_service('auth_db')
        id = str(service.post([credentials])[0])
        print('Session ID:', id)
        creds = service.find_one(req=None, _id=id)
        token = creds.get('token').encode('ascii')
        encoded_token = b'basic ' + b64encode(token + b':')
        print('Generated token: ', encoded_token)
        return encoded_token


superdesk.command('users:create', CreateUserCommand())
superdesk.command('users:modify', ManageUserCommand())
superdesk.command('users:hash_passwords', HashUserPasswordsCommand())
superdesk.command('users:get_auth_token', GetAuthTokenCommand())
