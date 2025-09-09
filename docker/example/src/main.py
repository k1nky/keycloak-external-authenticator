import asyncio
import uvicorn
from dataclasses import dataclass
from datetime import datetime
import logging
from typing import Optional

from authlib.integrations.starlette_client import OAuth, OAuthError
from authlib.jose import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Form
from pydantic_settings import BaseSettings
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse
from urllib.parse import urlparse, urlunparse


logging.basicConfig(
    format="%(levelname)s [%(asctime)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.DEBUG
)

class Settings(BaseSettings):
    oidc_client_id: str
    oidc_client_secret: str
    session_secret_key: str
    oidc_config_endpoint: str

    class Config:
        env_file = ".env"


settings = Settings()

app = FastAPI()
app.add_middleware(
    SessionMiddleware, secret_key=settings.session_secret_key
)

oauth = OAuth()
oauth.register(
    name='keycloak',
    server_metadata_url=settings.oidc_config_endpoint,
    client_id=settings.oidc_client_id,
    client_secret=settings.oidc_client_secret,
    client_kwargs={"scope": "openid profile"},
    access_token_params=None,
    authorize_params=None,
)


class UnauthenticatedError(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=401, detail="You are not authenticated.")


async def verify_token(id_token: str):
    jwks = await oauth.keycloak.fetch_jwk_set()
    try:
        decoded_jwt = jwt.decode(s=id_token, key=jwks)
        logging.info(f"New user created! jwt={decoded_jwt}")
    except Exception:
        logging.exception("An error occurred while decoding jwt.")
        raise UnauthenticatedError()
    metadata = await oauth.keycloak.load_server_metadata()
    if decoded_jwt["iss"] != metadata["issuer"]:
        raise UnauthenticatedError()
    if decoded_jwt["aud"] != settings.oidc_client_id:
        raise UnauthenticatedError()
    exp = datetime.fromtimestamp(decoded_jwt["exp"])
    if exp < datetime.now():
        raise UnauthenticatedError()
    return decoded_jwt


async def verify_user(request: Request):
    id_token = request.session.get("id_token")
    if id_token is None:
        raise UnauthenticatedError()
    decoded_jwt = await verify_token(id_token=id_token)
    user_id = decoded_jwt["sub"]
    user_repo = UserRepository()
    user = user_repo.select_by_user_id(user_id=user_id)
    if user is None:
        raise UnauthenticatedError()
    return user


@dataclass
class User:
    id: str
    name: str


class UserRepository:
    users: list[User] = []

    def select_by_user_id(self, user_id: str) -> Optional[User]:
        for user in self.users:
            if user.id == user_id:
                return user
        return None

    def insert(self, user: User) -> None:
        self.users.append(user)


@app.get("/api/login")
async def login(request: Request):
    redirect_uri = request.url_for('auth')
    redirect_uri = urlunparse(urlparse(str(redirect_uri))._replace(scheme=request.url.scheme))
    return await oauth.keycloak.authorize_redirect(request, redirect_uri)


@app.get("/api/auth")
async def auth(request: Request):
    try:
        token = await oauth.keycloak.authorize_access_token(request)
    except OAuthError:
        logging.exception("An error occurred while verifying authorization response.")
        raise UnauthenticatedError()
    userinfo = token.get("userinfo")
    if not userinfo:
        raise ValueError()
    user_dict = dict(userinfo)
    user_repo = UserRepository()
    user_id = user_dict["sub"]
    name = user_dict["preferred_username"]
    user = user_repo.select_by_user_id(user_id=user_id)
    if user is None:
        user = User(id=user_id, name=name)
        user_repo.insert(user=user)
        logging.info(f"New user created! user_id={user.id} name={user.name}")
    else:
        logging.info(
            f"The user exists; skipped registration. user_id={user.id} name={user.name}"
        )
    request.session["id_token"] = token.get("id_token")
    return RedirectResponse(url="/")


@app.get("/api/logout")
async def logout(request: Request, user: User = Depends(verify_user)):
    logging.info(f"A user logged out: user_id={user.id} name={user.name}")
    request.session.pop("id_token")
    return RedirectResponse(url="/")


@app.get("/api/userinfo")
async def userinfo(request: Request, user: User = Depends(verify_user)):
    logging.info(f"Successful log in: user_id={user.id} name={user.name}")
    return {
        "userinfo": {
            "id": user.id,
            "name": user.name,
        }
    }


@app.post("/api/external_auth")
async def mfa(r: Request):
    json_body = await r.json()
    logging.info(f"MFA: {json_body}")
    if json_body['attributes']['username'] == 'user2':
        raise UnauthenticatedError()


async def main() -> None:
    web_server = uvicorn.Server(
        config=uvicorn.Config(
            app=app,
            port=8080,
            use_colors=True,
            host="127.0.0.1",
        )
    )
    asyncio.create_task(web_server.serve())


if __name__ == "__main__":
    asyncio.run(main())
