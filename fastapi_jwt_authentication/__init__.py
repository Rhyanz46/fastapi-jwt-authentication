from pydantic import BaseModel, Field
from enum import Enum

from starlette.requests import Request
from fastapi.security.base import SecurityBase
from fastapi.security.utils import get_authorization_scheme_param
from typing import Optional, Dict

from starlette.status import HTTP_403_FORBIDDEN, HTTP_401_UNAUTHORIZED
from fastapi.exceptions import HTTPException


class SecuritySchemeType(Enum):
    apiKey = "apiKey"
    http = "http"
    oauth2 = "oauth2"
    openIdConnect = "openIdConnect"


class OAuthFlowsModel(BaseModel):
    refreshUrl: Optional[str] = None
    scopes: Dict[str, str] = {}


class OAuthFlowImplicit(OAuthFlowsModel):
    authorizationUrl: str


class OAuthFlowPassword(OAuthFlowsModel):
    tokenUrl: str


class OAuthFlowClientCredentials(OAuthFlowsModel):
    tokenUrl: str


class OAuthFlowAuthorizationCode(OAuthFlowsModel):
    authorizationUrl: str
    tokenUrl: str


class OAuthFlows(BaseModel):
    token: Optional[OAuthFlowImplicit] = None
    password: Optional[OAuthFlowPassword] = None
    clientCredentials: Optional[OAuthFlowClientCredentials] = None
    authorizationCode: Optional[OAuthFlowAuthorizationCode] = None


class OAuth2(SecurityBase):
    type_ = Field(SecuritySchemeType.oauth2, alias="type")
    flows: OAuthFlows


class Auth(SecurityBase):
    def __init__(
        self,
        *,
        scheme_name: Optional[str] = None,
        auto_error: Optional[bool] = True
    ):
        self.model = OAuthFlows()
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
