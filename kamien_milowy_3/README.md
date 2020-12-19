## Informacje ogólne:
- zmiana statusu przesyłki następuje w kolejności "W drodze" -> "Dostarczona" -> "Odebrana"
- usługa sieciowa działa pod adresem https://peaceful-taiga-22196.herokuapp.com/


## Aplikacja dla klienta (możliwości uruchomienia):
#### 1) Heroku
Aplikację została wdrożona na Heroku i jest dostępna pod linkiem:
https://serene-plateau-04196.herokuapp.com/

#### 2) Lokalnie z usługą sieciową z Heroku:
W wierszu poleceń należy wpisać "sh run_web_app.sh heroku"

#### 3) Lokalnie z lokalną usługą sieciową
W wierszu poleceń należy wpisać "sh run_web_app.sh local"

## Aplikacja dla kuriera (możliwości uruchomienia):

#### 1) Usługa sieciowa z heroku:
W katalogu "courier" należy wpisać polecenie "python3 app_courier"

#### 2) Lokalna usługa sieciowa:
W jednym terminalu należy przejść do katalogu "webservice" i wpisać "python3 app.py".
W drugim terminalu w katalogu "courier" należy wpisać polecenie "python3 app_courier local"

