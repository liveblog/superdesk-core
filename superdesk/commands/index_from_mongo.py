# -*- coding: utf-8; -*-
#
# This file is part of Superdesk.
#
# Copyright 2013 - 2015 Sourcefabric z.u. and contributors.
#
# For the full copyright and license information, please see the
# AUTHORS and LICENSE files distributed with this source code, or
# at https://www.sourcefabric.org/superdesk/license

import time
import arrow
import pymongo
import superdesk

from flask import current_app as app
from superdesk.errors import BulkIndexError
from superdesk import config


class IndexFromMongo(superdesk.Command):
    """Index the specified mongo collection in the specified elastic collection/type.

    This will use the default APP mongo DB to read the data and the default Elastic APP index.

    Use ``-f all`` to index all collections.

    Example:
    ::
        $ python manage.py app:index_from_mongo --from=archive
        $ python manage.py app:index_from_mongo --all
        $ python manage.py app:index_from_mongo --from-datetime '1991-09-17T00:00:00'
    """

    option_list = [
        superdesk.Option('--from', '-f', dest='collection_name'),
        superdesk.Option('--all', action='store_true', dest='all_collections'),
        superdesk.Option('--page-size', '-p'),
        superdesk.Option('--from-datetime', dest='from_datetime')
    ]
    default_page_size = 500

    def run(self, collection_name, all_collections, page_size, from_datetime):
        datetime_value = None
        if from_datetime:
            try:
                datetime_value = arrow.get(from_datetime).datetime
            except Exception:
                raise SystemExit('Unable to parse datetime parameter. Try format like `1991-09-17T00:00:00`')

        if not collection_name and not all_collections:
            raise SystemExit('Specify --all to index from all collections')
        elif all_collections:
            app.data.init_elastic(app)
            resources = app.data.get_elastic_resources()
            for resource in resources:
                self._copy_resource(resource, page_size, datetime_value)
        else:
            self._copy_resource(collection_name, page_size, datetime_value)

    def _copy_resource(self, resource, page_size, datetime_value):
        for items in self.get_mongo_items(resource, page_size, datetime_value):
            print('{} Inserting {} items'.format(time.strftime('%X %x %Z'), len(items)))
            s = time.time()

            for i in range(1, 4):
                try:
                    success, failed = superdesk.app.data._search_backend(resource).bulk_insert(
                        resource, items)
                except Exception as ex:
                    print('Exception thrown on insert to elastic {}', ex)
                    time.sleep(10)
                    continue
                else:
                    break

            print('{} Inserted {} items in {:.3f} seconds'.format(time.strftime('%X %x %Z'), success, time.time() - s))
            if failed:
                print('Failed to do bulk insert of items {}. Errors: {}'.format(len(failed), failed))
                raise BulkIndexError(resource=resource, errors=failed)

        return 'Finished indexing collection {}'.format(resource)

    def get_mongo_items(self, mongo_collection_name, page_size, datetime_value=None):
        """Generate list of items from given mongo collection per page size.

        :param mongo_collection_name: Name of the collection to get the items
        :param page_size: Size of every list in each iteration
        :return: list of items
        """
        bucket_size = int(page_size) if page_size else self.default_page_size
        print('Indexing data from mongo/{} to elastic/{}'.format(mongo_collection_name, mongo_collection_name))

        db = app.data.get_mongo_collection(mongo_collection_name)
        args = {'limit': bucket_size, 'sort': [(config.ID_FIELD, pymongo.ASCENDING)]}
        last_id = None

        if datetime_value:
            args['filter'] = {config.LAST_UPDATED: {'$gt': datetime_value}}

        while True:
            if last_id:
                filter = args.get('filter', {})
                filter[config.ID_FIELD] = {'$gt': last_id}
                args['filter'] = filter

            cursor = db.find(**args)
            if not cursor.count():
                break
            items = list(cursor)
            last_id = items[-1][config.ID_FIELD]
            yield items


superdesk.command('app:index_from_mongo', IndexFromMongo())
