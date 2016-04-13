# -*- coding: utf-8; -*-
#
# This file is part of Superdesk.
#
# Copyright 2013, 2014 Sourcefabric z.u. and contributors.
#
# For the full copyright and license information, please see the
# AUTHORS and LICENSE files distributed with this source code, or
# at https://www.sourcefabric.org/superdesk/license


import unittest

from bson import ObjectId
from unittest.mock import MagicMock
from superdesk import get_resource_service
from test_factory import SuperdeskTestCase
from superdesk.utc import get_expiry_date, utcnow
from apps.archive.archive import SOURCE as ARCHIVE
from superdesk.errors import SuperdeskApiError
from datetime import timedelta, datetime
from pytz import timezone
from apps.archive.common import validate_schedule, remove_media_files, \
    format_dateline_to_locmmmddsrc, convert_task_attributes_to_objectId, \
    is_genre, BROADCAST_GENRE, get_default_source, set_default_source, \
    get_utc_schedule


class RemoveSpikedContentTestCase(SuperdeskTestCase):

    articles = [{'guid': 'tag:localhost:2015:69b961ab-2816-4b8a-a584-a7b402fed4f9',
                 '_id': '1',
                 'type': 'text',
                 'last_version': 3,
                 '_current_version': 4,
                 'body_html': 'Test body',
                 'urgency': 4,
                 'headline': 'Two students missing',
                 'pubstatus': 'usable',
                 'firstcreated': utcnow(),
                 'byline': 'By Alan Karben',
                 'ednote': 'Andrew Marwood contributed to this article',
                 'keywords': ['Student', 'Crime', 'Police', 'Missing'],
                 'subject':[{'qcode': '17004000', 'name': 'Statistics'},
                            {'qcode': '04001002', 'name': 'Weather'}],
                 'state': 'draft',
                 'expiry': utcnow() + timedelta(minutes=20),
                 'unique_name': '#1'},
                {'guid': 'tag:localhost:2015:69b961ab-2816-4b8a-a974-xy4532fe33f9',
                 '_id': '2',
                 'last_version': 3,
                 '_current_version': 4,
                 'body_html': 'Test body of the second article',
                 'urgency': 4,
                 'headline': 'Another two students missing',
                 'pubstatus': 'usable',
                 'firstcreated': utcnow(),
                 'byline': 'By Alan Karben',
                 'ednote': 'Andrew Marwood contributed to this article',
                 'keywords': ['Student', 'Crime', 'Police', 'Missing'],
                 'subject':[{'qcode': '17004000', 'name': 'Statistics'},
                            {'qcode': '04001002', 'name': 'Weather'}],
                 'expiry': utcnow() + timedelta(minutes=20),
                 'state': 'draft',
                 'type': 'text',
                 'unique_name': '#2'},
                {'guid': 'tag:localhost:2015:69b961ab-2816-4b8a-a584-a7b402fed4fa',
                 '_id': '3',
                 '_current_version': 4,
                 'body_html': 'Test body',
                 'urgency': 4,
                 'headline': 'Two students missing killed',
                 'pubstatus': 'usable',
                 'firstcreated': utcnow(),
                 'byline': 'By Alan Karben',
                 'ednote': 'Andrew Marwood contributed to this article killed',
                 'keywords': ['Student', 'Crime', 'Police', 'Missing'],
                 'subject':[{'qcode': '17004000', 'name': 'Statistics'},
                            {'qcode': '04001002', 'name': 'Weather'}],
                 'state': 'draft',
                 'expiry': utcnow() + timedelta(minutes=20),
                 'type': 'text',
                 'unique_name': '#3'},
                {'guid': 'tag:localhost:2015:69b961ab-2816-4b8a-a584-a7b402fed4fc',
                 '_id': '4',
                 '_current_version': 3,
                 'state': 'draft',
                 'type': 'composite',
                 'groups': [{'id': 'root', 'refs': [{'idRef': 'main'}], 'role': 'grpRole:NEP'},
                            {
                                'id': 'main',
                                'refs': [
                                    {
                                        'location': 'archive',
                                        'guid': '1',
                                        'residRef': '1',
                                        'type': 'text'
                                    },
                                    {
                                        'location': 'archive',
                                        'residRef': '2',
                                        'guid': '2',
                                        'type': 'text'
                                    }
                                ],
                                'role': 'grpRole:main'}],
                 'firstcreated': utcnow(),
                 'expiry': utcnow() + timedelta(minutes=20),
                 'unique_name': '#4'},
                {'guid': 'tag:localhost:2015:69b961ab-4b8a-a584-2816-a7b402fed4fc',
                 '_id': '5',
                 '_current_version': 3,
                 'state': 'draft',
                 'type': 'composite',
                 'groups': [{'id': 'root', 'refs': [{'idRef': 'main'}, {'idRef': 'story'}], 'role': 'grpRole:NEP'},
                            {
                                'id': 'main',
                                'refs': [
                                    {
                                        'location': 'archive',
                                        'guid': '1',
                                        'residRef': '1',
                                        'type': 'text'
                                    }
                                ],
                                'role': 'grpRole:main'},
                            {
                                'id': 'story',
                                'refs': [
                                    {
                                        'location': 'archive',
                                        'guid': '4',
                                        'residRef': '4',
                                        'type': 'composite'
                                    }
                                ],
                                'role': 'grpRole:story'}],
                 'firstcreated': utcnow(),
                 'expiry': utcnow() + timedelta(minutes=20),
                 'unique_name': '#5'}]

    media = {
        'viewImage': {
            'media': '1592730d582080f4e9fcc2fcf43aa357bda0ed19ffe314ee3248624cd4d4bc54',
            'mimetype': 'image/jpeg',
            'href': 'http://192.168.220.209/api/upload/abc/raw?_schema=http',
            'height': 452,
            'width': 640
        },
        'thumbnail': {
            'media': '52250b4f37da50ee663fdbff057a5f064479f8a8bbd24fb8fdc06135d3f807bb',
            'mimetype': 'image/jpeg',
            'href': 'http://192.168.220.209/api/upload/abc/raw?_schema=http',
            'height': 120,
            'width': 169
        },
        'baseImage': {
            'media': '7a608aa8f51432483918027dd06d0ef385b90702bfeba84ac4aec38ed1660b18',
            'mimetype': 'image/jpeg',
            'href': 'http://192.168.220.209/api/upload/abc/raw?_schema=http',
            'height': 990,
            'width': 1400
        },
        'original': {
            'media': 'stub.jpeg',
            'mimetype': 'image/jpeg',
            'href': 'http://192.168.220.209/api/upload/stub.jpeg/raw?_schema=http',
            'height': 2475,
            'width': 3500
        }
    }

    def setUp(self):
        super().setUp()

    def test_query_getting_expired_content(self):
        self.app.data.insert(ARCHIVE, [{'expiry': get_expiry_date(-10), 'state': 'spiked'}])
        self.app.data.insert(ARCHIVE, [{'expiry': get_expiry_date(0), 'state': 'spiked'}])
        self.app.data.insert(ARCHIVE, [{'expiry': get_expiry_date(10), 'state': 'spiked'}])
        self.app.data.insert(ARCHIVE, [{'expiry': get_expiry_date(20), 'state': 'spiked'}])
        self.app.data.insert(ARCHIVE, [{'expiry': get_expiry_date(30), 'state': 'spiked'}])
        self.app.data.insert(ARCHIVE, [{'expiry': None, 'state': 'spiked'}])
        self.app.data.insert(ARCHIVE, [{'unique_id': 97, 'state': 'spiked'}])

        now = utcnow()
        expired_items = get_resource_service(ARCHIVE).get_expired_items(now)
        self.assertEquals(1, expired_items.count())

    def test_query_removing_media_files_keeps(self):
        self.app.data.insert(ARCHIVE, [{'state': 'spiked',
                                        'expiry': get_expiry_date(-10),
                                        'type': 'picture',
                                        'renditions': self.media}])

        self.app.data.insert('ingest', [{'type': 'picture', 'renditions': self.media}])
        self.app.data.insert('archive_versions', [{'type': 'picture', 'renditions': self.media}])
        self.app.data.insert('legal_archive', [{'_id': 1, 'type': 'picture', 'renditions': self.media}])
        self.app.data.insert('legal_archive_versions', [{'_id': 1, 'type': 'picture', 'renditions': self.media}])

        archive_items = self.app.data.find_all('archive', None)
        self.assertEqual(archive_items.count(), 1)
        deleted = remove_media_files(archive_items[0])
        self.assertFalse(deleted)

    def test_delete_by_ids(self):
        ids = self.app.data.insert(ARCHIVE, self.articles)
        archive_service = get_resource_service(ARCHIVE)
        archive_service.on_delete = MagicMock()
        archive_service.delete_by_article_ids(ids)
        self.assertTrue(self.app.data.mongo.is_empty(ARCHIVE))
        self.assertTrue(self.app.data.elastic.is_empty(ARCHIVE))
        self.assertEqual(len(self.articles), archive_service.on_delete.call_count)


class ArchiveTestCase(SuperdeskTestCase):
    def test_validate_schedule(self):
        validate_schedule(utcnow() + timedelta(hours=2))

    def test_validate_schedule_date_with_datetime_as_string_raises_superdeskApiError(self):
        self.assertRaises(SuperdeskApiError, validate_schedule, "2015-04-27T10:53:48+00:00")

    def test_validate_schedule_date_with_datetime_in_past_raises_superdeskApiError(self):
        self.assertRaises(SuperdeskApiError, validate_schedule, utcnow() + timedelta(hours=-2))

    def _get_located_and_current_utc_ts(self):
        current_ts = utcnow()
        located = {"dateline": "city", "city_code": "Sydney", "state": "NSW", "city": "Sydney", "state_code": "NSW",
                   "country_code": "AU", "tz": "Australia/Sydney", "country": "Australia"}

        current_timestamp = datetime.fromtimestamp(current_ts.timestamp(), tz=timezone(located['tz']))
        if current_timestamp.month == 9:
            formatted_date = 'Sept {}'.format(current_timestamp.strftime('%d'))
        elif 3 <= current_timestamp.month <= 7:
            formatted_date = current_timestamp.strftime('%B %d')
        else:
            formatted_date = current_timestamp.strftime('%b %d')

        return located, formatted_date, current_ts

    def test_format_dateline_to_format_when_only_city_is_present(self):
        located, formatted_date, current_ts = self._get_located_and_current_utc_ts()
        formatted_dateline = format_dateline_to_locmmmddsrc(located, current_ts)
        self.assertEqual(formatted_dateline, 'SYDNEY %s %s -' % (formatted_date, get_default_source()))

    def test_format_dateline_to_format_when_only_city_and_state_are_present(self):
        located, formatted_date, current_ts = self._get_located_and_current_utc_ts()

        located['dateline'] = "city,state"
        formatted_dateline = format_dateline_to_locmmmddsrc(located, current_ts)
        self.assertEqual(formatted_dateline, 'SYDNEY, NSW %s %s -' % (formatted_date, get_default_source()))

    def test_format_dateline_to_format_when_only_city_and_country_are_present(self):
        located, formatted_date, current_ts = self._get_located_and_current_utc_ts()

        located['dateline'] = "city,country"
        formatted_dateline = format_dateline_to_locmmmddsrc(located, current_ts)
        self.assertEqual(formatted_dateline, 'SYDNEY, AU %s %s -' % (formatted_date, get_default_source()))

    def test_format_dateline_to_format_when_city_state_and_country_are_present(self):
        located, formatted_date, current_ts = self._get_located_and_current_utc_ts()

        located['dateline'] = "city,state,country"
        formatted_dateline = format_dateline_to_locmmmddsrc(located, current_ts)
        self.assertEqual(formatted_dateline, 'SYDNEY, NSW, AU %s %s -' % (formatted_date, get_default_source()))

    def test_if_task_attributes_converted_to_objectid(self):
        doc = {
            'task': {
                'user': '562435231d41c835d7b5fb55',
                'desk': ObjectId("562435241d41c835d7b5fb5d"),
                'stage': 'test',
                'last_authoring_desk': 3245,
                'last_production_desk': None
            }
        }

        convert_task_attributes_to_objectId(doc)
        self.assertIsInstance(doc['task']['user'], ObjectId)
        self.assertEqual(doc['task']['desk'], ObjectId("562435241d41c835d7b5fb5d"))
        self.assertEqual(doc['task']['stage'], 'test')
        self.assertEqual(doc['task']['last_authoring_desk'], 3245)
        self.assertIsNone(doc['task']['last_production_desk'])

    def test_if_no_source_defined_on_desk(self):
        desk = {'name': 'sports'}
        self.app.data.insert('desks', [desk])
        located, formatted_date, current_ts = self._get_located_and_current_utc_ts()
        doc = {
            '_id': '123',
            'task': {
                'desk': desk['_id'],
                'stage': desk['working_stage']
            },
            'dateline': {
                'located': located,
                'date': current_ts
            }
        }

        set_default_source(doc)
        self.assertEqual(doc['source'], get_default_source())
        self.assertEqual(doc['dateline']['source'], get_default_source())
        self.assertEqual(doc['dateline']['text'], 'SYDNEY %s %s -' % (formatted_date,
                                                                      get_default_source()))

    def test_if_source_defined_on_desk(self):
        source = 'FOO'
        desk = {'name': 'sports', 'source': source}
        self.app.data.insert('desks', [desk])
        located, formatted_date, current_ts = self._get_located_and_current_utc_ts()
        doc = {
            '_id': '123',
            'task': {
                'desk': desk['_id'],
                'stage': desk['working_stage']
            },
            'dateline': {
                'located': located,
                'date': current_ts
            }
        }

        set_default_source(doc)
        self.assertEqual(doc['source'], source)
        self.assertEqual(doc['dateline']['source'], source)
        self.assertEqual(doc['dateline']['text'], 'SYDNEY %s %s -' % (formatted_date, source))


class ArchiveCommonTestCase(unittest.TestCase):

    def test_broadcast_content(self):
        content = {
            'genre': [{'name': 'Broadcast Script', 'qcode': 'Broadcast Script'}]
        }

        self.assertTrue(is_genre(content, BROADCAST_GENRE))

    def test_broadcast_content_if_genre_is_none(self):
        content = {
            'genre': None
        }

        self.assertFalse(is_genre(content, BROADCAST_GENRE))

    def test_broadcast_content_if_genre_is_empty_list(self):
        content = {
            'genre': []
        }

        self.assertFalse(is_genre(content, BROADCAST_GENRE))

    def test_broadcast_content_if_genre_is_other_than_broadcast(self):
        content = {
            'genre': [{'name': 'Article', 'qcode': 'Article'}]
        }

        self.assertFalse(is_genre(content, BROADCAST_GENRE))
        self.assertTrue(is_genre(content, 'Article'))

    def test_get_utc_schedule(self):
        embargo_date = utcnow() + timedelta(minutes=10)
        content = {
            'embargo': embargo_date
        }
        utc_schedule = get_utc_schedule(content, 'embargo')
        self.assertEqual(utc_schedule, embargo_date)


class ExpiredArchiveContentTestCase(SuperdeskTestCase):

    def setUp(self):
        super().setUp()
        try:
            from apps.archive.commands import RemoveExpiredContent
        except ImportError:
            self.fail("Could not import class under test (RemoveExpiredContent).")
        else:
            self.class_under_test = RemoveExpiredContent
            self.published_items = [
                {
                    '_id': 'item1', 'item_id': 'item1', 'headline': 'headline',
                    'source': 'aap', 'body_html': 'test', '_current_version': 3,
                    'moved_to_legal': True
                },
                {
                    '_id': 'item2', 'item_id': 'item2', 'headline': 'headline',
                    'source': 'aap', 'body_html': 'test', '_current_version': 3,
                    'moved_to_legal': True
                },
                {
                    '_id': 'item3', 'item_id': 'item3', 'headline': 'headline',
                    'source': 'aap', 'body_html': 'test', '_current_version': 3,
                    'moved_to_legal': False
                },
                {
                    '_id': 'item4', 'item_id': 'item4', 'headline': 'headline',
                    'source': 'aap', 'body_html': 'test', '_current_version': 3,
                    'moved_to_legal': True
                }
            ]

            self.queue_items = [
                {
                    '_id': 'item1', 'item_id': 'item1', 'headline': 'headline',
                    'item_version': 3, 'moved_to_legal': True
                },
                {
                    '_id': 'item2', 'item_id': 'item2', 'headline': 'headline',
                    'source': 'aap', 'body_html': 'test', 'item_version': 3,
                    'moved_to_legal': True
                },
                {
                    '_id': 'item3', 'item_id': 'item3', 'headline': 'headline',
                    'source': 'aap', 'body_html': 'test', 'item_version': 3,
                    'moved_to_legal': False
                },
                {
                    '_id': 'item4', 'item_id': 'item4', 'headline': 'headline',
                    'source': 'aap', 'body_html': 'test', 'item_version': 3,
                    'moved_to_legal': False
                },
                {
                    '_id': 'item5', 'item_id': 'item4', 'headline': 'headline',
                    'source': 'aap', 'body_html': 'test', 'item_version': 3,
                    'moved_to_legal': True
                }
            ]

            self.app.data.insert('published', self.published_items)
            self.app.data.insert('publish_queue', self.queue_items)

    def test_items_moved_to_legal_success(self):
        result = self.class_under_test().check_if_items_imported_to_legal_archive(['item1', 'item2'])
        self.assertEqual(result, True)

    def test_items_moved_to_legal_fail_if_published_item_not_moved(self):
        result = self.class_under_test().check_if_items_imported_to_legal_archive(['item2', 'item3'])
        self.assertEqual(result, False)

    def test_items_moved_to_legal_fail_if_published_queue_item_not_moved(self):
        result = self.class_under_test().check_if_items_imported_to_legal_archive(['item1', 'item4'])
        self.assertEqual(result, False)