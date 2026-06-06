from fastapi import FastAPI

from contextlib import asynccontextmanager

def setup_api(db):
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        db.close()

    app = FastAPI(lifespan=lifespan)

    @app.get('/test', summary='Test endpoint')
    async def test_endpoint():
        return { 'message': 'Hello World' }

    return app
