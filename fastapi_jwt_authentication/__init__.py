from pydantic import BaseModel

from starlette.requests import Request
from fastapi.security.base import SecurityBase
from fastapi.security.utils import get_authorization_scheme_param
from typing import Optional

from starlette.status import HTTP_403_FORBIDDEN, HTTP_401_UNAUTHORIZED
from fastapi.exceptions import HTTPException


class AuthFlowsModel(BaseModel):
    pass


class AuthFlows(BaseModel):
    token: Optional[AuthFlowsModel] = None


class Auth(SecurityBase):
    def __init__(
        self,
        *,
        scheme_name: Optional[str] = None,
        auto_error: Optional[bool] = True
    ):
        self.model = AuthFlows()
        self.scheme_name = scheme_name or self.__class__.__name__
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization")
        if not authorization:
            if self.auto_error:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authenticated")
            else:
                return None
        return authorization


class BearerAuth(Auth):
    def __init__(
        self,
        scheme_name: Optional[str] = None,
        auto_error: bool = True,
    ):
        super().__init__(scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None
        return param
