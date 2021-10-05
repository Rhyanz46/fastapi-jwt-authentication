# fastapi-jwt-authentication

example :
```python
from fastapi import FastAPI, Depends
from pydantic import BaseModel
from typing import Optional

from fastapi.security import OAuth2PasswordBearer
from fastapi_jwt_authentication import BearerAuth

app = FastAPI()
bearer_auth_schema = BearerAuth()
oauth2_schema = OAuth2PasswordBearer(tokenUrl="token")


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


def fake_decode_token(token):
    return User(username=token + "fakedecoded", email="john@example.com", full_name="John Doe")


async def get_current_user(token: str = Depends(bearer_auth_schema)):
    user = fake_decode_token(token)
    return user


@app.get("/api/user")
async def me(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/api/checkk")
async def kabupaten_get(token: User = Depends(get_current_user)):
    print(token)
    return {"status": "berhasil"}


@app.get('/api/test')
async def aa(token: OAuth2PasswordBearer(tokenUrl="token") = Depends()):
    print(token)
    return "google"
```
