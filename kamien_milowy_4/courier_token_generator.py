import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
from os import getenv


load_dotenv('webservice/.env')
JWT_SECRET = getenv('JWT_SECRET')

payload = {
        
        "exp": datetime.utcnow() + timedelta(days=365),
        "usr": "Courier"
    }
token = jwt.encode(payload, JWT_SECRET, algorithm='HS256').decode()
print(token)
