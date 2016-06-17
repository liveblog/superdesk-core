# -*- coding: utf-8; -*-
#
# This file is part of Superdesk.
#
# Copyright 2013, 2014 Sourcefabric z.u. and contributors.
#
# For the full copyright and license information, please see the
# AUTHORS and LICENSE files distributed with this source code, or
# at https://www.sourcefabric.org/superdesk/license
from superdesk.metadata.item import ITEM_STATE, CONTENT_STATE
import superdesk
import logging
from superdesk.errors import SuperdeskApiError
from superdesk.notification import push_notification
from superdesk.users.services import current_user_has_privilege
from superdesk.utc import utcnow
from superdesk.lock import lock, unlock
from eve.utils import config

from apps.common.components.base_component import BaseComponent
from apps.common.models.utils import get_model
from apps.content import push_content_notification

from ..models.item import ItemModel


LOCK_USER = 'lock_user'
LOCK_SESSION = 'lock_session'
STATUS = '_status'
TASK = 'task'
logger = logging.getLogger(__name__)


class ItemLock(BaseComponent):
    def __init__(self, app):
        self.app = app
        self.app.on_session_end += self.on_session_end

    @classmethod
    def name(cls):
        return 'item_lock'

    def lock(self, item_filter, user_id, session_id, etag):
        item_model = get_model(ItemModel)
        item = item_model.find_one(item_filter)

        # set the lock_id it per item
        lock_id = "item_lock {}".format(item.get(config.ID_FIELD))

        if not item:
            raise SuperdeskApiError.notFoundError()

        # get the lock it not raise forbidden exception
        if not lock(lock_id, "", 5):
            raise SuperdeskApiError.forbiddenError(message="Item is locked by another user.")

        try:
            can_user_lock, error_message = self.can_lock(item, user_id, session_id)

            if can_user_lock:
                self.app.on_item_lock(item, user_id)
                updates = {LOCK_USER: user_id, LOCK_SESSION: session_id, 'lock_time': utcnow()}
                item_model.update(item_filter, updates)

                if item.get(TASK):
                    item[TASK]['user'] = user_id
                else:
                    item[TASK] = {'user': user_id}

                superdesk.get_resource_service('tasks').assign_user(item[config.ID_FIELD], item[TASK])
                self.app.on_item_locked(item, user_id)
                push_notification('item:lock',
                                  item=str(item.get(config.ID_FIELD)),
                                  item_version=str(item.get(config.VERSION)),
                                  user=str(user_id), lock_time=updates['lock_time'],
                                  lock_session=str(session_id))
            else:
                raise SuperdeskApiError.forbiddenError(message=error_message)

            item = item_model.find_one(item_filter)
            return item
        except Exception as e:
            raise e
        finally:
            # unlock the lock :)
            unlock(lock_id)

    def unlock(self, item_filter, user_id, session_id, etag):
        item_model = get_model(ItemModel)
        item = item_model.find_one(item_filter)

        if not item:
            raise SuperdeskApiError.notFoundError()

        if not item.get(LOCK_USER):
            raise SuperdeskApiError.badRequestError(message="Item is not locked.")

        can_user_unlock, error_message = self.can_unlock(item, user_id)

        if can_user_unlock:
            self.app.on_item_unlock(item, user_id)

            # delete the item if nothing is saved so far
            # version 0 created on lock item
            if item.get(config.VERSION, 0) == 0 and item[ITEM_STATE] == CONTENT_STATE.DRAFT:
                superdesk.get_resource_service('archive').delete_action(lookup={'_id': item['_id']})
                push_content_notification([item])
            else:
                updates = {LOCK_USER: None, LOCK_SESSION: None, 'lock_time': None, 'force_unlock': True}
                item_model.update(item_filter, updates)
                self.app.on_item_unlocked(item, user_id)

            push_notification('item:unlock',
                              item=str(item_filter.get(config.ID_FIELD)),
                              item_version=str(item.get(config.VERSION)),
                              state=item.get(ITEM_STATE),
                              user=str(user_id), lock_session=str(session_id))
        else:
            raise SuperdeskApiError.forbiddenError(message=error_message)

        item = item_model.find_one(item_filter)
        return item

    def unlock_session(self, user_id, session_id):
        item_model = get_model(ItemModel)
        items = item_model.find({'lock_session': session_id})

        for item in items:
            self.unlock({'_id': item['_id']}, user_id, session_id, None)

    def can_lock(self, item, user_id, session_id):
        """
        Function checks whether user can lock the item or not. If not then raises exception.
        """
        can_user_edit, error_message = superdesk.get_resource_service('archive').can_edit(item, user_id)

        if can_user_edit:
            if item.get(LOCK_USER):
                if str(item.get(LOCK_USER, '')) == str(user_id) and str(item.get(LOCK_SESSION)) != str(session_id):
                    return False, 'Item is locked by you in another session.'
                else:
                    if str(item.get(LOCK_USER, '')) != str(user_id):
                        return False, 'Item is locked by another user.'
        else:
            return False, error_message

        return True, ''

    def can_unlock(self, item, user_id):
        """
        Function checks whether user can unlock the item or not.
        """
        can_user_edit, error_message = superdesk.get_resource_service('archive').can_edit(item, user_id)

        if can_user_edit:
            if not (str(item.get(LOCK_USER, '')) == str(user_id) or
                    (current_user_has_privilege('archive') and current_user_has_privilege('unlock'))):
                return False, 'You don\'t have permissions to unlock an item.'
        else:
            return False, error_message

        return True, ''

    def on_session_end(self, user_id, session_id):
        self.unlock_session(user_id, session_id)
