from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from database import Base, engine, get_db
from models import *
from schemas import UserCreate, UserResponse, Token, OrganizationResponse,PasswordResetConfirm,PasswordResetRequest
from pydantic import BaseModel, EmailStr
from auth import get_password_hash, verify_password, create_access_token, get_current_user, create_reset_token, verify_reset_token
from typing import List

app = FastAPI()

Base.metadata.create_all(bind=engine)

    


@app.post("users/",response_model=UserResponse)  
async def create_user(user: UserCreate,db:Session= Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    db_user = User(
        fulname = user.full_name,
        email = user.email, 
        password = hashed_password,
        is_verified = False,
        is_organization = False
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post('token/',response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password,user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Email not verified",)
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token" : access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user
    

@app.post("/password-reset/")
async def requeest_password_reset(request: PasswordResetRequest,db:Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    reset_token = create_reset_token(data={"sub": user.email})
    return {"reset_token": reset_token, "message": "Password reset token sent to email"}


@app.post("/password-reset/confirm/")
async def confirm_password_reset(request: PasswordResetConfirm, db: Session = Depends(get_db)):
    user = await verify_reset_token(request.token, db)
    user.password = get_password_hash(request.new_password)
    db.commit()
    return {"message": "Password successfully reset"}



@app.post('create-organization/')
async def create_organization(name: str, category: str, description: str, address: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user.is_organization:
        raise HTTPException(status_code=403, detail="User is not an organization")
    
    organization = Organization(
        name=name,
        category=category,
        description=description,
        address=address,
        owner_id=current_user.id
    )
    db.add(organization)
    db.commit()
    db.refresh(organization)
    return organization




@app.post("create-branch/")
async def create_branch(name: str, address: str, schedule: dict, organization_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user.is_organization:
        raise HTTPException(status_code=403, detail="User is not an organization")
    
    organization = db.query(Organization).filter(Organization.id == organization_id, Organization.owner_id == current_user.id).first()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found or user is not the owner")
    
    branch = Branch(
        name=name,
        address=address,
        schedule=schedule,
        organization_id=organization_id
    )
    db.add(branch)
    db.commit()
    db.refresh(branch)
    return branch



@app.post("create-queue-slot/")
async def create_queue_slot(branch_id: int, user_id: int, date: str, time: str, status: str, db: Session = Depends(get_db)):
    queue_slot = QueueSlot(
        branch_id=branch_id,
        user_id=user_id,
        date=date,
        time=time,
        status=status
    )
    db.add(queue_slot)
    db.commit()
    db.refresh(queue_slot)
    return queue_slot


@app.get("/queue-slots/", response_model=List[QueueSlot])
async def get_queue_slots(db: Session = Depends(get_db)):
    queue_slots = db.query(QueueSlot).all()
    return queue_slots



@app.get("/branches/", response_model=List[Branch])
async def get_branches(db: Session = Depends(get_db)):
    branches = db.query(Branch).all()
    return branches


@app.get('/organizations/', response_model=List[OrganizationResponse])
async def get_organizations(db: Session = Depends(get_db)):
    organizations = db.query(Organization).all()
    return organizations


@app.get('/organizations/{organization_id}/', response_model=OrganizationResponse)
async def get_organization(organization_id: int, db: Session = Depends(get_db)):
    organization = db.query(Organization).filter(Organization.id == organization_id).first()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")
    return organization


@app.get('/users/', response_model=List[UserResponse])
async def get_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users

@app.get('/users/{user_id}/', response_model=UserResponse)
async def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.patch('quick-queue-slot/{slot_id}/')
async def update_queue_slot(slot_id: int, status: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    queue_slot = db.query(QueueSlot).filter(QueueSlot.id == slot_id, QueueSlot.user_id == current_user.id).first()
    if not queue_slot:
        raise HTTPException(status_code=404, detail="Queue slot not found or user is not the owner")
    
    queue_slot.status = status
    db.commit()
    db.refresh(queue_slot)
    return queue_slot

@app.patch('quick-branch/{branch_id}/')
async def update_branch(branch_id: int, name: str, address: str, schedule: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    branch = db.query(Branch).filter(Branch.id == branch_id, Branch.organization_id == current_user.id).first()
    if not branch:
        raise HTTPException(status_code=404, detail="Branch not found or user is not the owner")
    
    branch.name = name
    branch.address = address
    branch.schedule = schedule
    db.commit()
    db.refresh(branch)
    return branch

@app.patch('quick-organization/{organization_id}/')
async def update_organization(organization_id: int, name: str, category: str, description: str, address: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    organization = db.query(Organization).filter(Organization.id == organization_id, Organization.owner_id == current_user.id).first()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found or user is not the owner")
    
    organization.name = name
    organization.category = category
    organization.description = description
    organization.address = address
    db.commit()
    db.refresh(organization)
    return organization

@app.delete('quick-queue-slot/{slot_id}/')
async def delete_queue_slot(slot_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    queue_slot = db.query(QueueSlot).filter(QueueSlot.id == slot_id, QueueSlot.user_id == current_user.id).first()
    if not queue_slot:
        raise HTTPException(status_code=404, detail="Queue slot not found or user is not the owner")
    
    db.delete(queue_slot)
    db.commit()
    return {"message": "Queue slot deleted successfully"}

@app.delete('quick-branch/{branch_id}/')
async def delete_branch(branch_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    branch = db.query(Branch).filter(Branch.id == branch_id, Branch.organization_id == current_user.id).first()
    if not branch:
        raise HTTPException(status_code=404, detail="Branch not found or user is not the owner")
    
    db.delete(branch)
    db.commit()
    return {"message": "Branch deleted successfully"}

@app.delete('quick-organization/{organization_id}/')
async def delete_organization(organization_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    organization = db.query(Organization).filter(Organization.id == organization_id, Organization.owner_id == current_user.id).first()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found or user is not the owner")
    
    db.delete(organization)
    db.commit()
    return {"message": "Organization deleted successfully"}
