import pika
from sys import exit
from dotenv import load_dotenv
from os import getenv
import json
from terminaltables import AsciiTable
from datetime import datetime
load_dotenv('.env')

Q_HOST = getenv("Q_HOST")
Q_LOGIN = getenv("Q_LOGIN")
Q_PASSWORD = getenv("Q_PASSWORD")
Q_VH = getenv("Q_VH")


credentials = pika.PlainCredentials(Q_LOGIN, Q_PASSWORD)

parameters = pika.ConnectionParameters(Q_HOST, 5672, Q_VH, credentials)

connection = pika.BlockingConnection(parameters)

channel = connection.channel()

channel.queue_declare(queue="invoices")


def callback(ch, method, properties, body):
    invoice_data = json.loads(body.decode())
    print("New invoice")

    table = []
    column_name = ["Usługa", "Rozmiar paczki","Wartość [zł]"]
    table.append(column_name)
    table.append(["Wysyłka paczki", invoice_data['size'], invoice_data['cost']])
    table_view = AsciiTable(table)
    file = open(f"faktura_vat_{invoice_data['id']}.txt","w")
    file.write("            FAKTURA VAT \n\n"
               "Data wystawienia:\n"
               f"{datetime.today().strftime('%d-%m-%Y')}\n\n"
               "Sprzedawca:\n"
               "Firma kurierska 'Paczuszka'\n"
               "Piotr Rzewnicki\n\n"
               "Odbiorca:\n"
               f"{invoice_data['sender']}\n{invoice_data['adress']}\n\n"
               f"{table_view.table}\n\n"
               f"Uwagi:\n"
               f"Paczka o numerze {invoice_data['id']}"
               )
    file.close()
    ch.basic_ack(delivery_tag=method.delivery_tag, multiple=False)


channel.basic_consume(queue='invoices',
                      auto_ack=False,
                      on_message_callback=callback)

try:
    print(' [*] Waiting for invoices. To exit press CTRL+C')
    channel.start_consuming()
except KeyboardInterrupt:
    print('Interrupted')
    connection.close()
    exit(0)
