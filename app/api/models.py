from typing import List
from pydantic import BaseModel

SECRET_KEY = 'minimal-secret-key'
JWT_ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRES_MINUTES = 10


class User(BaseModel):
    email: str
    password: str


class Token(BaseModel):
    access_token: str


class JWTSettings(BaseModel):
    authjwt_secret_key: str = SECRET_KEY
    authjwt_algorithm: str = JWT_ALGORITHM
    authjwt_access_token_expires: int = ACCESS_TOKEN_EXPIRES_MINUTES