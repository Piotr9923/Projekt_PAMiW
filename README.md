## Celem projektu jest stworzenie aplikacji internetowej do zarządzania paczkomatami.

### Pierwszy kamień milowy
W pierwszym kamieniu milowym należało zaimplementować formularz rejestracji z walidacją wprowadzonych danych.

<br/>
### Drugi kamień milowy

Celem drugiego kamienia milowego było rozbudowanie aplikacji o możliwość logowania użytkowników. W tym celu należało skorzystać z bazy danych Redis. Po zalogowaniu użytkownik ma możliwość utworzenia etykiety paczki, a na swojej tablicy wyświetla wszystkie utworzone etykiety.

<br/>
### Trzeci kamień milowy

Trzeci kamień milowy opierał się na zaimplementowaniu usługi sieciowej w architekturze REST, a także dwóch jej klientów:
- aplikacji webowej na nadawcy,
- aplikacji dla kuriera.

Aplikacja webowa dla nadawcy ma takie same funkcjonalnośći jak w drugim kamieniu milowym.
Aplikacja dla kuriera umożliwa wyświetlenie listy wszystkich etykiet, utworzenie paczki na podstawie etykiety, a także zmianę statusu paczki.

<br/>
### Czwarty kamień milowy
W czwartym kamieniu milowym należało do obu aplikacji klienckich zaimplementować możliwość autoryzacji za pomocą zewnętrznego serwisu autoryzacyjnego  (wybrałem auth0.com). Należało również rozbudować aplikację dla nadawcy o system powiadomień na temat paczki.
