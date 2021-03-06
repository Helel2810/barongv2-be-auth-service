from fastapi import FastAPI
from app.api.users import users


app = FastAPI()


app.include_router(users)
