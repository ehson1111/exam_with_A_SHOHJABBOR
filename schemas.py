from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
from datetime import datetime

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
        from_attributes = True  

class Token(BaseModel):
    access_token: str
    token_type: str

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
        from_attributes = True  

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

class QueueSlotBase(BaseModel):
    branch_id: int
    user_id: int
    date: datetime  # Changed to datetime to match SQLAlchemy model
    time: str
    status: str

    class Config:
        from_attributes = True

class QueueSlotCreate(QueueSlotBase):
    pass

class QueueSlot(QueueSlotBase):
    id: int

class BranchBase(BaseModel):
    name: str
    address: str
    schedule: Dict[str, Any]
    organization_id: int

    class Config:
        from_attributes = True

class BranchCreate(BranchBase):
    pass

class Branch(BranchBase):
    id: int