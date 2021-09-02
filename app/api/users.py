from fastapi import Header, APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_jwt_auth import AuthJWT

from app.api.models import User, Token, JWTSettings


@AuthJWT.load_config
def load_config():
    return JWTSettings()


users = APIRouter()


def authenticate_user(username: str, password: str):
    if username != 'demo@minimals.cc':
        return False
    if password != 'demo1234':
        return False

    return {'id': '8864c717-587d-472a-929a-8e5f298024da-0'}


@users.post('/token', response_model=Token)
async def login_for_access_token(form_data: User, authorize: AuthJWT = Depends()):
    user = authenticate_user(form_data.email, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect Email or Passwords"
        )
    access_token = authorize.create_access_token(subject=user['id'])
    return {'access_token': access_token}


