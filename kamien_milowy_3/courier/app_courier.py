import os
import requests
import sys
from dotenv import load_dotenv
from os import getenv
from terminaltables import AsciiTable

load_dotenv('.env')

WEBSERVICE_URL = getenv("WEBSERVICE_URL")

if len(sys.argv)>1:
    if sys.argv[1] == "local":
        WEBSERVICE_URL = getenv("LOCAL_WEBSERVICE_URL")

print(WEBSERVICE_URL)

HEADER = {"Authorization": f"Bearer {getenv('TOKEN')}"}


def get_labels(is_not_send):
    try:
        header = HEADER
        header["is_not_send"] = str(is_not_send)
        url = WEBSERVICE_URL + "/labels"
        response = requests.get(url, headers=header)
        if response.status_code == 200:
            return response.json()["labels"]
        else:
            for error in response.json()["errors"]:
                print(error)
            return "ERROR"
    except Exception as e:
        print("Wystąpił błąd połączenia z usługą sieciową")
        return "ERROR"


def get_packages():
    try:
        url = WEBSERVICE_URL + "/packages"
        response = requests.get(url, headers=HEADER)
        if response.status_code == 200:
            return response.json()['packages']
        else:
            for error in response.json()["errors"]:
                print(error)
            return "ERROR"
    except Exception as e:
        print("Wystąpił błąd połączenia z usługą sieciową")
        return "ERROR"


def create_package(label_id):
    try:
        url = WEBSERVICE_URL + "/packages"
        response = requests.post(url, json={"label_id":label_id}, headers=HEADER)
        if response.status_code == 200:
            return True
        else:
            for error in response.json()["errors"]:
                print(error)
            return "ERROR"
    except Exception as e:
        print("Wystąpił błąd połączenia z usługą sieciową")
        return "ERROR"


def change_status(package_id):
    try:
        url = WEBSERVICE_URL + "/packages/" + package_id
        response = requests.put(url, json={"package_id": package_id}, headers=HEADER)
        if response.status_code == 200:
            return True
        else:
            for error in response.json()["errors"]:
                print(error)
            return "ERROR"
    except Exception as e:
        print("Wystąpił błąd połączenia z usługą sieciową")
        return "ERROR"


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("****************************************************")
    print("* Witaj kurierze. Aby uruchomić pomoc wpisz \'help\' *")
    print("****************************************************")


def show_help():
    print("")
    print("Dostępne polecenia:")
    print("'clear' - wyczyszczenie konsoli")
    print("'all' - wyświetlenie wszystkich etykiet i paczek")
    print("'labels' - wyświetlenie wszystkich etykiet, które nie zostały nadane")
    print("'packages' - wyświetlenie wszystkich paczek")
    print("'create-package' - utworzenie paczki")
    print("'change-status' - zmiana status paczki")
    print("'exit' - wyjście z programu")


def exit_app():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("****************************************************")
    print("*             Do widzenia kurierze                 *")
    print("****************************************************")
    exit(0)


def show_lables(is_not_send):
    labels = get_labels(is_not_send)
    if labels != "ERROR":
        column_name = ["ID", "Odbiorca", "ID punktu odbioru", "Rozmiar", "Login nadawcy"]
        if is_not_send == False:
            column_name.append("Status")
        table = []
        table.append(column_name)
        for label in labels:
            table_row=[]
            table_row.append(label['id'])
            table_row.append(label['name'])
            table_row.append(label['delivery_id'])
            table_row.append(label['size'])
            table_row.append(label['sender'])
            if is_not_send == False:
                table_row.append(label['status'])
            table.append(table_row)

        table_view = AsciiTable(table)
        print(table_view.table)


def show_packages():
    packages = get_packages()
    if packages != "ERROR":
        column_name = ["ID", "Odbiorca", "ID punktu odbioru", "Rozmiar", "Login nadawcy", "Status"]
        table = []
        table.append(column_name)
        for package in packages:
            table_row = []
            table_row.append(package['id'])
            table_row.append(package['name'])
            table_row.append(package['delivery_id'])
            table_row.append(package['size'])
            table_row.append(package['sender'])
            table_row.append(package['status'])
            table.append(table_row)

        table_view = AsciiTable(table)
        print(table_view.table)


def show_create_package():
    label_id = input("ID etykiety: ")

    correct_create = create_package(label_id)

    if correct_create == True:
        print("")
        print("Poprawnie utworzono paczkę")
    else:
        print("")
        print("Paczka nie została utworzona")


def show_change_status():
    package_id = input("ID paczki: ")

    correct_create = change_status(package_id)

    if correct_create == True:
        print("")
        print("Poprawnie zmieniono status paczki")
    else:
        print("")
        print("Status paczki nie został zmieniony")



clear()

while True:
    print("")
    choice = input(">> ")

    if choice == "help":
        show_help()
    elif choice == "help":
        show_help()
    elif choice == "clear":
        clear()
    elif choice == "labels":
        show_lables(True)
    elif choice == "packages":
        show_packages()
    elif choice == "all":
        show_lables(False)
    elif choice == "create-package":
        show_create_package()
    elif choice == "change-status":
        show_change_status();
    elif choice == "exit":
        exit_app()
    else:
        print("Błędne polecenie")
