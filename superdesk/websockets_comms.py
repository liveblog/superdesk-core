#!/usr/bin/env python
# -*- coding: utf-8; -*-
#
# This file is part of Superdesk.
#
# Copyright 2013, 2014, 2015 Sourcefabric z.u. and contributors.
#
# For the full copyright and license information, please see the
# AUTHORS and LICENSE files distributed with this source code, or
# at https://www.sourcefabric.org/superdesk/license


import arrow
import atexit
import itertools
import logging
import asyncio
import os
import queue
import threading
import time
import websockets
import signal

from datetime import timedelta
from threading import Thread
from kombu import Queue, Exchange, Connection
from kombu.mixins import ConsumerMixin
from kombu.pools import producers
from superdesk.utc import utcnow
from superdesk.utils import get_random_string
from superdesk.default_settings import celery_queue, WS_HEART_BEAT
from flask import json


logger = logging.getLogger(__name__)

# Notifications are sent from API requests and Celery tasks, which must never wait on the broker.
# The producer only queues them; one background thread per process publishes, retrying while the
# broker is down or not answering. A message older than PRODUCER_MAX_MESSAGE_AGE is dropped instead
# of sent late: by then it is stale for the editors' screens. See LBSD-2994.
PRODUCER_CONNECT_TIMEOUT = 2
PRODUCER_RETRY_POLICY = {'max_retries': 1, 'interval_start': 0, 'interval_step': 0.5, 'interval_max': 0.5}
PRODUCER_RETRY_DELAYS = (0.5, 1, 2, 5)
PRODUCER_MAX_MESSAGE_AGE = 20
PRODUCER_QUEUE_SIZE = 1000
PRODUCER_EXIT_FLUSH_TIMEOUT = 2


class SocketBrokerClient:
    """
    Base class for web socket notification using broker (redis or rabbitmq)
    """

    connection = None

    def __init__(self, url, exchange_name=None):
        self.url = url
        self.connect()
        self.exchange_name = exchange_name if exchange_name else celery_queue('socket_notification')
        self.channel = self.connection.channel()
        self.socket_exchange = Exchange(self.exchange_name, type='fanout', channel=self.channel)
        self.socket_exchange.declare()

    def open(self):
        """Test if connection is open.

        True if connected else false

        :return bool:
        """
        return self.connection and self.connection.connected

    def connect(self):
        self._close()
        logger.info('Connecting to broker {}'.format(self.url))
        self.connection = Connection(self.url, heartbeat=WS_HEART_BEAT)
        self.connection.connect()
        logger.info('Connected to broker {}'.format(self.url))

    def _close(self):
        if hasattr(self, 'connection') and self.connection:
            logger.info('Closing connecting to broker {}'.format(self.url))
            self.connection.release()
            self.connection = None
            logger.info('Connection closed to broker {}'.format(self.url))

    def close(self):
        self._close()


class SocketMessageProducer(SocketBrokerClient):
    """Publishes messages to a fanout exchange from a background thread."""

    def __init__(self, url, exchange_name=None):
        # Does not connect: the sender thread does, so building the producer never waits on the broker.
        self.url = url
        self.exchange_name = exchange_name if exchange_name else celery_queue('socket_notification')
        self.socket_exchange = Exchange(self.exchange_name, type='fanout')
        self._lock = threading.Lock()
        self._pid = None
        self._queue = None
        atexit.register(self._flush)

    def send(self, message):
        """Queue the message for publishing and return immediately.

        :param string message: message to publish
        """
        self._start_sender()
        try:
            self._queue.put_nowait((time.monotonic(), message))
        except queue.Full:
            logger.warning('Notification queue is full, dropping message {}'.format(message))

    def _start_sender(self):
        # Threads do not survive fork and gunicorn and Celery fork after the app is built, so each
        # process gets its own queue, thread and connection. The parent's connection is dropped, not
        # closed: closing it would close the socket the parent still uses.
        if self._pid == os.getpid():
            return
        with self._lock:
            if self._pid == os.getpid():
                return
            self.connection = None
            self._queue = queue.Queue(maxsize=PRODUCER_QUEUE_SIZE)
            threading.Thread(target=self._send_forever, name='notification-sender', daemon=True).start()
            self._pid = os.getpid()

    def _send_forever(self):
        failing = False
        while True:
            created, message = self._queue.get()
            delays = itertools.chain(PRODUCER_RETRY_DELAYS, itertools.repeat(PRODUCER_RETRY_DELAYS[-1]))
            for delay in delays:
                if time.monotonic() - created > PRODUCER_MAX_MESSAGE_AGE:
                    logger.warning('Dropping notification older than {}s: {}'.format(
                        PRODUCER_MAX_MESSAGE_AGE, message))
                    break
                try:
                    self._publish(message)
                except Exception:
                    if not failing:
                        logger.exception('Failed to publish notifications to broker {}, retrying'.format(self.url))
                        failing = True
                    time.sleep(delay)
                else:
                    if failing:
                        logger.warning('Publishing notifications to broker {} again'.format(self.url))
                        failing = False
                    break
            self._queue.task_done()

    def _publish(self, message):
        if self.connection is None:
            self.connection = Connection(
                self.url,
                heartbeat=WS_HEART_BEAT,
                connect_timeout=PRODUCER_CONNECT_TIMEOUT,
                transport_options=dict(PRODUCER_RETRY_POLICY),
            )
        with producers[self.connection].acquire(block=True) as producer:
            producer.publish(
                message,
                exchange=self.socket_exchange,
                declare=[self.socket_exchange],
                retry=True,
                retry_policy=PRODUCER_RETRY_POLICY,
            )
            logger.debug('message:{} published to broker:{}.'.format(message, self.url))

    def _flush(self):
        """On a clean exit, give the thread a moment to publish what is still queued."""
        if self._pid != os.getpid():
            return
        deadline = time.monotonic() + PRODUCER_EXIT_FLUSH_TIMEOUT
        while self._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.05)


class SocketMessageConsumer(SocketBrokerClient, ConsumerMixin):
    """
    Consumer of the message.
    """

    def __init__(self, url, callback, exchange_name=None):
        """Create consumer.

        :param string url: Broker URL
        :param string host: host name running the websocket server
        :param callback: callback function to call on message arrival
        """
        super().__init__(url, exchange_name)
        self.callback = callback
        self.queue_name = 'socket_consumer_{}'.format(get_random_string())
        # expire message after 10 seconds and queue after 60 seconds
        self.queue = Queue(self.queue_name, exchange=self.socket_exchange,
                           channel=self.channel,
                           queue_arguments={'x-message-ttl': 10000, 'x-expires': 60000})

    def get_consumers(self, Consumer, channel):
        return [Consumer(queues=[self.queue], callbacks=[self.on_message])]

    def on_message(self, body, message):
        """
        Event fired when message is received by the queue

        :param str body:
        :param kombu.Message message: Message object
        """
        try:
            try:
                loop = asyncio.get_event_loop()
            except Exception:
                loop = asyncio.new_event_loop()

            logger.info('Queue: {}. Broadcasting message {}'.format(self.queue_name, body))
            loop.run_until_complete(self.callback(body))
        except Exception:
            logger.exception('Dropping event. Failed to send message {}.'.format(body))
        try:
            message.ack()
        except Exception:
            logger.exception('Failed to ack message {} on queue {}.'.format(body, self.queue_name))

    def close(self):
        """
        Closing the consumer.

        :return:
        """
        logger.info('closing consumer')
        self.should_stop = True
        super().close()
        logger.info('consumer terminated successfully')


class SocketCommunication:
    """
    Responsible for websocket comms.
    """

    clients = set()

    def __init__(self, host, port, broker_url, exchange_name=None):
        self.host = host
        self.port = port
        self.broker_url = broker_url
        self.exchange_name = exchange_name
        self.messages = {}
        self.event_interval = {
            'ingest:update': 5,
            'ingest:cleaned': 5,
            'content:expired': 5,
            'publish_queue:update': 5,
        }

    @asyncio.coroutine
    def _client_loop(self, websocket):
        """Client loop - send it ping every `beat_delay` seconds to keep it alive.

        Nginx would close the connection after 2 minutes of inactivity, that's why.

        Also it does the health check - if socket was closed by client it will
        break the loop and let server deregister the client.

        :param websocket: websocket protocol instance
        """
        pings = 0
        while True:
            yield from asyncio.sleep(5)
            if not websocket.open:
                break
            pings += 1

            host, port = websocket.remote_address
            yield from websocket.send(json.dumps({
                    'ping': pings, 'clients': len(websocket.ws_server.websockets),
                    'address': '%s:%s' % (host, port)
                }))

    @asyncio.coroutine
    def broadcast(self, message):
        """Broadcast message to all clients.

        If event is in `event_interval` it will only send such event every x seconds.

        :param message: message as it was received - no encoding/decoding.
        """
        message_data = json.loads(message)
        message_id = message_data.get('event', '')
        message_created = arrow.get(message_data.get('_created', utcnow()))
        last_created = self.messages.get(message_id)
        ttl = self.event_interval.get(message_id, 0)

        if last_created and last_created + timedelta(seconds=ttl) > message_created:
            logger.info('skiping event %s' % (message_id, ))
            return

        if ttl:
            self.messages[message_id] = message_created

        logger.debug('broadcast %s' % message)
        for websocket in self.clients.copy():
            try:
                if websocket.open:
                    yield from websocket.send(message)
            except Exception as err:
                host, port = websocket.remote_address
                logger.exception('Problem broadcasting message to address=%s:%s. Error: %s' % (host, port, err))
                yield

    @asyncio.coroutine
    def _server_loop(self, websocket):
        """Server loop - wait for message and broadcast it.

        :param websocket: websocket protocol instance
        """
        while True:
            message = yield from websocket.recv()
            yield from self.broadcast(message)

    def _log(self, message, websocket):
        """Log message with some websocket data like address.

        :param message: message string
        :param websocket: websocket protocol instance
        """
        host, port = websocket.remote_address
        logger.info('%s address=%s:%s' % (message, host, port))

    @asyncio.coroutine
    def _connection_handler(self, websocket, path):
        """Handle incomming connections.

        When this function returns the session is over and it closes the socket,
        so there must be some loops..

        :param websocket: websocket protocol instance
        :param path: url path used by client - used to identify client/server connections
        """
        if 'server' in path:
            self._log('server open', websocket)
            yield from self._server_loop(websocket)
            self._log('server done', websocket)
        else:
            self._log('client open', websocket)
            self.clients.add(websocket)
            yield from self._client_loop(websocket)
            self.clients.remove(websocket)
            self._log('client done', websocket)

    def run_server(self):
        """Create websocket server and run it until it gets Ctrl+C or SIGTERM.

        :param config: config dictionary
        """
        try:
            loop = asyncio.get_event_loop()
            server = loop.run_until_complete(websockets.serve(self._connection_handler,
                                                              self.host, self.port))
            loop.add_signal_handler(signal.SIGTERM, loop.stop)
            logger.info('listening on %s:%s' % (self.host, self.port))
            consumer = None
            # create socket message consumer
            consumer = SocketMessageConsumer(self.broker_url, self.broadcast, self.exchange_name)
            consumer_thread = Thread(target=consumer.run)
            consumer_thread.start()
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            logger.info('closing server')
            server.close()
            loop.run_until_complete(server.wait_closed())
            loop.stop()
            loop.run_forever()
            loop.close()
            if consumer:
                consumer.close()
