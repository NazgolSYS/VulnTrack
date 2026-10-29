
from typing import Annotated

from pydantic import BaseModel, StringConstraints


NonEmptyString = Annotated[
    str,
    StringConstraints(min_length=1),
]

NonBlankUsername = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1),
]


class LoginRequest(BaseModel):
    username: NonBlankUsername
    password: NonEmptyString


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
