from pydantic import BaseModel, EmailStr
from typing import Optional

class UserCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    full_name: str
    email: EmailStr
    is_verified: bool
    is_organization: bool

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str