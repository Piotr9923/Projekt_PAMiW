#!bin/sh

if [ $# -eq 0 ]
  then
    echo "Podaj parametr heroku lub local"
    exit
fi


if [ $1 = 'local' ];
then 
    echo "SECRET_KEY='adnsoSIDASONDSianoads3278da8sada87dsaa%%^@'\nJWT_SECRET=\"SECERET\"\nWEBSERVICE_URL=http://webservice:5000" > web/.env
elif [ $1 = 'heroku' ];
then
    echo "SECRET_KEY='adnsoSIDASONDSianoads3278da8sada87dsaa%%^@'\nJWT_SECRET=\"SECERET\"\nWEBSERVICE_URL=https://peaceful-taiga-22196.herokuapp.com/" > web/.env
else
echo "Podaj parametr heroku lub local"
    exit
fi

docker-compose build
docker-compose up

