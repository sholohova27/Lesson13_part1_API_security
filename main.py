from fastapi import FastAPI
from src.router import router
from src.middleware.cors import setup_cors

app = FastAPI()

setup_cors(app)

app.include_router(router)
