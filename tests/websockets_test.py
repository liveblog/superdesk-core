
import asyncio
import threading
import time
import unittest
from unittest import mock
from json import dumps
from datetime import datetime, timedelta
from superdesk import websockets_comms
from superdesk.websockets_comms import SocketCommunication


class TestClient():

    def __init__(self):
        self.open = True
        self.messages = []

    def send(self, message):
        self.messages.append(message)


class WebsocketsTestCase(unittest.TestCase):

    def test_broadcast(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        client = TestClient()
        com = SocketCommunication('host', 'port', 'url')
        com.clients.add(client)

        loop.run_until_complete(com.broadcast(dumps({
            'event': 'ingest:update',
            '_created': datetime.now().isoformat()})))
        self.assertEqual(1, len(client.messages))

        loop.run_until_complete(com.broadcast(dumps({
            'event': 'ingest:update',
            '_created': datetime.now().isoformat()})))
        self.assertEqual(1, len(client.messages))

        loop.run_until_complete(com.broadcast(dumps({
            'event': 'foo',
            '_created': datetime.now().isoformat()})))
        self.assertEqual(2, len(client.messages))

        loop.run_until_complete(com.broadcast(dumps({
            'event': 'foo',
            '_created': datetime.now().isoformat()})))
        self.assertEqual(3, len(client.messages))

        loop.run_until_complete(com.broadcast(dumps({
            'event': 'ingest:update',
            '_created': (datetime.now() + timedelta(seconds=3600)).isoformat()})))
        self.assertEqual(4, len(client.messages))


class SocketMessageProducerTestCase(unittest.TestCase):
    """The producer must never make the caller wait on the broker, see LBSD-2994."""

    def setUp(self):
        self.producer = websockets_comms.SocketMessageProducer('amqp://localhost:1//', 'test')
        self.published = []
        self.failures = 0

    def fake_publish(self, message):
        if self.failures:
            self.failures -= 1
            raise OSError('broker down')
        self.published.append(message)

    def wait_until_sent(self):
        self.producer._queue.join()

    def test_send_does_not_publish_in_the_caller(self):
        release = threading.Event()
        with mock.patch.object(self.producer, '_publish', side_effect=lambda m: release.wait(5)):
            started = time.monotonic()
            self.producer.send('one')
            self.assertLess(time.monotonic() - started, 0.5)
            release.set()
            self.wait_until_sent()

    def test_retries_until_the_broker_answers(self):
        self.failures = 2
        with mock.patch.object(websockets_comms, 'PRODUCER_RETRY_DELAYS', (0.01,)), \
                mock.patch.object(self.producer, '_publish', side_effect=self.fake_publish):
            self.producer.send('one')
            self.producer.send('two')
            self.wait_until_sent()
        self.assertEqual(self.published, ['one', 'two'])

    def test_drops_messages_older_than_the_max_age(self):
        self.failures = 1000
        with mock.patch.object(websockets_comms, 'PRODUCER_RETRY_DELAYS', (0.05,)), \
                mock.patch.object(websockets_comms, 'PRODUCER_MAX_MESSAGE_AGE', 0.2), \
                mock.patch.object(self.producer, '_publish', side_effect=self.fake_publish):
            self.producer.send('old')
            self.wait_until_sent()
            self.failures = 0
            self.producer.send('new')
            self.wait_until_sent()
        self.assertEqual(self.published, ['new'])
