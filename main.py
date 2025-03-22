# main.py (Entry point and Routing)
from fastapi import FastAPI, Depends, HTTPException, Path, Security, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, EmailStr, constr, validator
from typing import List, Optional
import controllers
import models
import database
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import jwt
import os
from fastapi.responses import JSONResponse

app = FastAPI()

SECRET_KEY = os.environ.get("SECRET_KEY", "secret")  # Replace with a strong, secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Utility Functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return email
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(token: str = Security(oauth2_scheme), db: Session = Depends(database.get_db)):
    email = decode_token(token)
    user = db.query(database.User).filter(database.User.email == email).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# Endpoints

@app.post("/signup/", response_model=models.Token)
def signup(user: models.UserCreate, user_controller: controllers.UserController = Depends(controllers.get_user_controller)):
    db_user = user_controller.create_user(user.email, user.password)
    access_token = create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/login/", response_model=models.Token)
def login(user: models.UserLogin, user_controller: controllers.UserController = Depends(controllers.get_user_controller)):
    db_user = user_controller.authenticate_user(user.email, user.password)
    if not db_user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/addpost/", response_model=models.PostResponse)
def add_post(post: models.PostCreate, current_user: database.User = Depends(get_current_user), post_controller: controllers.PostController = Depends(controllers.get_post_controller)):
    if len(post.text.encode('utf-8')) > 1024 * 1024: #1MB limit
        raise HTTPException(status_code=413, detail="Payload too large")
    db_post = post_controller.create_post(post.text, current_user.id)
    return db_post

@app.get("/getposts/", response_model=List[models.PostResponse])
async def get_posts(current_user: database.User = Depends(get_current_user), post_controller: controllers.PostController = Depends(controllers.get_post_controller), request: Request):

    cache_key = f"posts:{current_user.id}"
    cached_response = await app.state.redis.get(cache_key)

    if cached_response:
        return JSONResponse(content=eval(cached_response))

    posts = post_controller.get_posts(current_user.id)
    await app.state.redis.set(cache_key, str([p.dict() for p in posts]), ex=300) #cache for 5 minutes

    return posts

@app.delete("/deletepost/{post_id}", response_model=models.PostResponse)
def delete_post(post_id: int = Path(..., gt=0), current_user: database.User = Depends(get_current_user), post_controller: controllers.PostController = Depends(controllers.get_post_controller)):
    db_post = post_controller.delete_post(post_id, current_user.id)
    if not db_post:
        raise HTTPException(status_code=404, detail="Post not found")
    return db_post

# controllers.py (Business Logic)
import models
import database
from sqlalchemy.orm import Session
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserController:
    def __init__(self, db: Session):
        self.db = db

    def create_user(self, email: str, password: str):
        hashed_password = pwd_context.hash(password)
        db_user = database.User(email=email, hashed_password=hashed_password)
        self.db.add(db_user)
        self.db.commit()
        self.db.refresh(db_user)
        return db_user

    def authenticate_user(self, email: str, password: str):
        user = self.db.query(database.User).filter(database.User.email == email).first()
        if not user or not pwd_context.verify(password, user.hashed_password):
            return None
        return user

class PostController:
    def __init__(self, db: Session):
        self.db = db

    def create_post(self, text: str, user_id: int):
        db_post = database.Post(text=text, user_id=user_id)
        self.db.add(db_post)
        self.db.commit()
        self.db.refresh(db_post)
        return db_post

    def get_posts(self, user_id: int):
        return self.db.query(database.Post).filter(database.Post.user_id == user_id).all()

    def delete_post(self, post_id: int, user_id: int):
        post = self.db.query(database.Post).filter(database.Post.id == post_id, database.Post.user_id == user_id).first()
        if post:
            self.db.delete(post)
            self.db.commit()
            return post
        return None

def get_user_controller(db: Session = Depends(database.get_db)):
    return UserController(db)

def get_post_controller(db: Session = Depends(database.get_db)):
    return PostController(db)

# models.py (Data Models - Pydantic)
from pydantic import BaseModel, Field, EmailStr, constr

class UserCreate(BaseModel):
    email: EmailStr
    password: constr(min_length=8)

class UserLogin(BaseModel):
    email: EmailStr
    password: constr(min_length=8)

class Token(BaseModel):
    access_token: str
    token_type: str

class PostCreate(BaseModel):
    text: str

class PostResponse(BaseModel):
    id: int
    text: str
    user_id: int

# database.py (Database Interaction - SQLAlchemy)
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
import redis.asyncio as redis

DATABASE_URL = "mysql+pymysql://user:password@host/dbname" #Replace with your database credentials

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed
