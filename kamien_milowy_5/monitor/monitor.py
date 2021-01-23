import pika
from sys import exit
from dotenv import load_dotenv
from os import getenv

load_dotenv('.env')

Q_HOST = getenv("Q_HOST")
Q_LOGIN = getenv("Q_LOGIN")
Q_PASSWORD = getenv("Q_PASSWORD")
Q_VH = getenv("Q_VH")


credentials = pika.PlainCredentials(Q_LOGIN, Q_PASSWORD)

parameters = pika.ConnectionParameters(Q_HOST, 5672, Q_VH, credentials)

connection = pika.BlockingConnection(parameters)

channel = connection.channel()

channel.queue_declare(queue="errors")


def callback(ch, method, properties, body):
    print(body.decode())
    ch.basic_ack(delivery_tag=method.delivery_tag, multiple=False)


channel.basic_consume(queue='errors',
                      auto_ack=False,
                      on_message_callback=callback)

try:
    print(' [*] Waiting for messages. To exit press CTRL+C')
    channel.start_consuming()
except KeyboardInterrupt:
    print('Interrupted')
    connection.close()
    exit(0)
