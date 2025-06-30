from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from database import Base, engine, get_db
from models import User
from schemas import UserCreate, UserResponse, Token
from pydantic import BaseModel, EmailStr


app = FastAPI()

Base.metadata.create_all(bind=engine)

class PasswordResetRequest(BaseModel):
    email: str


class PAsswordReserConfirm(BaseModel):
    token: str
    new_password: str       


@app.post("users/",response_model=UserResponse)  
async def create_user(user: UserCreate,db:Session= Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    db_user = User(
        fulname = user.full_name,
        email = user.email, 
        password = hashed_password
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
