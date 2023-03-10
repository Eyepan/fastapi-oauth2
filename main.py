import jwt
import os
import bcrypt
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from database import initDB, connection
from users import User, UserIn, get_user_by_username, get_user_by_id, insert_user

load_dotenv()
app = FastAPI()

JWT_SECRET = os.getenv("JWT_SECRET")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@app.on_event("startup")
async def init():
    initDB()


@app.post("/token")
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_username(username=form_data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username",
        )
    if not user.verify_password(password=form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
        )
    token = jwt.encode({"id": user.user_id}, JWT_SECRET)
    return {"access_token": token, "token_type": "bearer"}


@app.post("/users")
async def post_create_user(user: UserIn) -> User:
    insert_user(username=user.username, password=user.password)
    user = get_user_by_username(username=user.username)
    return user


@app.get("/users/me")
async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = get_user_by_id(payload.get("id"))
        return user
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
