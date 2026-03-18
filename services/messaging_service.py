"""
RabbitMQ messaging helpers for event-driven agent communication.
"""

import json
from typing import Any, Callable

import pika

from configs.settings import settings
from services.logging_service import get_service_logger

logger = get_service_logger("messaging_service")


class RabbitMQClient:
    """Small wrapper around pika BlockingConnection for publish/consume flows."""

    def __init__(self):
        self._connection: pika.BlockingConnection | None = None
        self._channel: pika.adapters.blocking_connection.BlockingChannel | None = None

    @property
    def channel(self) -> pika.adapters.blocking_connection.BlockingChannel:
        if self._channel is None or self._channel.is_closed:
            self.connect()
        return self._channel

    def connect(self) -> None:
        credentials = pika.PlainCredentials(
            settings.rabbitmq_user,
            settings.rabbitmq_password,
        )
        parameters = pika.ConnectionParameters(
            host=settings.rabbitmq_host,
            port=settings.rabbitmq_port,
            credentials=credentials,
            heartbeat=60,
            blocked_connection_timeout=60,
        )
        self._connection = pika.BlockingConnection(parameters)
        self._channel = self._connection.channel()
        logger.info("RabbitMQ connected", host=settings.rabbitmq_host, port=settings.rabbitmq_port)

    def close(self) -> None:
        if self._connection and self._connection.is_open:
            self._connection.close()
            logger.info("RabbitMQ connection closed")

    def declare_new_email_fanout(self, queue_name: str) -> None:
        self.channel.exchange_declare(
            exchange=settings.new_email_exchange,
            exchange_type="fanout",
            durable=True,
        )
        self.channel.queue_declare(queue=queue_name, durable=True)
        self.channel.queue_bind(queue=queue_name, exchange=settings.new_email_exchange)

    def declare_results_queue(self, queue_name: str | None = None) -> str:
        queue_name = queue_name or settings.results_queue
        self.channel.queue_declare(queue=queue_name, durable=True)
        return queue_name

    def publish_new_email(self, payload: dict[str, Any]) -> None:
        self.channel.exchange_declare(
            exchange=settings.new_email_exchange,
            exchange_type="fanout",
            durable=True,
        )
        self.channel.basic_publish(
            exchange=settings.new_email_exchange,
            routing_key="",
            body=json.dumps(payload).encode("utf-8"),
            properties=pika.BasicProperties(delivery_mode=2),
        )

    def publish_to_queue(self, queue_name: str, payload: dict[str, Any]) -> None:
        self.channel.queue_declare(queue=queue_name, durable=True)
        self.channel.basic_publish(
            exchange="",
            routing_key=queue_name,
            body=json.dumps(payload).encode("utf-8"),
            properties=pika.BasicProperties(delivery_mode=2),
        )

    def consume(
        self,
        queue_name: str,
        callback: Callable[[dict[str, Any]], None],
        prefetch_count: int = 1,
    ) -> None:
        self.channel.queue_declare(queue=queue_name, durable=True)
        self.channel.basic_qos(prefetch_count=prefetch_count)

        def _wrapped(ch, method, _properties, body):
            try:
                payload = json.loads(body.decode("utf-8"))
                callback(payload)
                ch.basic_ack(delivery_tag=method.delivery_tag)
            except Exception as exc:
                logger.exception("Message processing failed", error=str(exc), queue=queue_name)
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

        self.channel.basic_consume(queue=queue_name, on_message_callback=_wrapped)
        logger.info("Consuming queue", queue=queue_name)
        self.channel.start_consuming()
