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

class Organization(BaseModel):
    name: str
    category: str
    description: Optional[str] = None
    address: Optional[str] = None
    owner_id: int


class OrganizationCreate(BaseModel):
    name: str
    category: str
    description: Optional[str] = None
    address: Optional[str] = None

class OrganizationResponse(BaseModel):
    id: int
    name: str
    category: str
    description: Optional[str] = None
    address: Optional[str] = None
    owner_id: int

    class Config:
        orm_mode = True



class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str
    