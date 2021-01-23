## Celem projektu jest stworzenie aplikacji internetowej do zarządzania paczkomatami.

### Pierwszy kamień milowy
W pierwszym kamieniu milowym należało zaimplementować formularz rejestracji z walidacją wprowadzonych danych.

### Drugi kamień milowy

Celem drugiego kamienia milowego było rozbudowanie aplikacji o możliwość logowania użytkowników. W tym celu należało skorzystać z bazy danych Redis. Po zalogowaniu użytkownik ma możliwość utworzenia etykiety paczki, a na swojej tablicy wyświetla wszystkie utworzone etykiety.

### Trzeci kamień milowy

Trzeci kamień milowy opierał się na zaimplementowaniu usługi sieciowej w architekturze REST, a także dwóch jej klientów:
- aplikacji webowej na nadawcy,
- aplikacji dla kuriera.

Aplikacja webowa dla nadawcy ma takie same funkcjonalnośći jak w drugim kamieniu milowym.
Aplikacja dla kuriera umożliwa wyświetlenie listy wszystkich etykiet, utworzenie paczki na podstawie etykiety, a także zmianę statusu paczki.

### Czwarty kamień milowy
W czwartym kamieniu milowym należało do obu aplikacji klienckich zaimplementować możliwość autoryzacji za pomocą zewnętrznego serwisu autoryzacyjnego  (wybrałem auth0.com). Należało również rozbudować aplikację dla nadawcy o system powiadomień na temat paczki.

### Piąty kamień milowy
Celem piątego kamienia milowego jest rozbudowanie aplikacji o system komunikatów realizowanych za pomocą kolejki RabbitMQ. Należy rozbudować aplikację kliencką oraz usłgę sieciową tak, aby wysyłały one wiadomości do kolejki komunikatów.
Należy stworzyć również dwóch odbiorców komunikatów:
-- monitor - wyświetla wszystkie komunikaty o błędach,
-- invoicer - generuje fakturę w postaci pliku tekstowego za każdym razem, gdy paczka zostanie odebrana przez kuriera.
