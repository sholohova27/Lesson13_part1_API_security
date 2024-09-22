from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
import jwt
from jwt import InvalidTokenError as JWTError
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request
import os
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader
from fastapi import File, UploadFile
from fastapi.security import OAuth2PasswordBearer


from src import schemas
from src import handler
from src.database.db import get_db
from src.schemas import Token, UserLogin
from src.database.models import verify_password, authenticate_user
from src.handler import create_access_token, create_refresh_token, get_user_by_email, get_current_user, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES


router = APIRouter(prefix='/contacts', tags=["contacts"])

limiter = Limiter(key_func=get_remote_address)

@router.post("/", response_model=schemas.ContactResponse)
@limiter.limit("5/minute")  # Ограничение на создание контактов
def create_contact(contact: schemas.ContactCreate, request: Request, db: Session = Depends(get_db)):
    return handler.create_contact(db, contact)


@router.get("/", response_model=List[schemas.ContactResponse])
def read_contacts(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    return handler.get_contacts(db, skip=skip, limit=limit)

@router.get("/{contact_id}", response_model=schemas.ContactResponse)
def read_contact(contact_id: int, db: Session = Depends(get_db)):
    db_contact = handler.get_contact(db, contact_id)
    if not db_contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return db_contact

@router.put("/{contact_id}", response_model=schemas.ContactResponse)
def update_contact(contact_id: int, contact: schemas.ContactUpdate, db: Session = Depends(get_db)):
    db_contact = handler.update_contact(db, contact_id, contact)
    if not db_contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return db_contact

@router.delete("/{contact_id}", response_model=schemas.ContactResponse)
def delete_contact(contact_id: int, db: Session = Depends(get_db)):
    db_contact = handler.delete_contact(db, contact_id)
    if not db_contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return db_contact

@router.get("/search", response_model=List[schemas.ContactResponse])
def search_contacts(name: str = None, surname: str = None, email: str = None, db: Session = Depends(get_db)):
    return handler.search_contacts(db, name=name, surname=surname, email=email)

@router.get("/birthdays", response_model=List[schemas.ContactResponse])
def get_upcoming_birthdays(db: Session = Depends(get_db)):
    return handler.get_upcoming_birthdays(db)


@router.post("/token", response_model=schemas.Token)
def login_for_access_token(form_data: UserLogin, db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.email, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post("/refresh", response_model=schemas.Token)
def refresh_token(refresh_token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = get_user_by_email(db, email=email)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.get("/verify")
def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        user = get_user_by_email(db, email)
        if user:
            user.is_verified = True
            db.commit()
            return {"msg": "Email successfully verified"}
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")

load_dotenv()
cloudinary.config(
  cloud_name=os.getenv("cloud_name"),
  api_key=os.getenv("api_key"),
  api_secret=os.getenv("api_secret")
)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@router.put("/avatar")
async def update_avatar(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    result = cloudinary.uploader.upload(file.file)
    user = get_current_user(db, token=oauth2_scheme(request))
    user.avatar_url = result['secure_url']
    db.commit()
    return {"msg": "Avatar updated", "avatar_url": result['secure_url']}