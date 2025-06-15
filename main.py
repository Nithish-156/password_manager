from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel
from firebase_config import db
import firebase_admin.auth as fb_auth
from fastapi.middleware.cors import CORSMiddleware
import auth
import uuid

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # or specify: ["https://yourfrontend.com"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- MODELS ----------
class RegisterModel(BaseModel):
    username: str
    password: str
    
class LoginModel(BaseModel):
    username: str
    password: str

class PasswordEntry(BaseModel):
    username: str
    game_name: str
    gmail: str
    password: str
    sony_password: str
    amount_spent: int

# ---------- HELPERS ----------
def get_user_id_from_token(token: str):
    decoded = auth.decode_token(token)
    if not decoded or "sub" not in decoded:
        raise HTTPException(status_code=401, detail="Invalid token")
    return decoded["sub"]

# ---------- ROUTES ----------
@app.post("/register")
def register(user: RegisterModel):
    try:
        user_record = fb_auth.create_user(
            email=user.username,
            password=user.password
        )
        return {"message": "User registered", "uid": user_record.uid}
    except fb_auth.EmailAlreadyExistsError:
        raise HTTPException(status_code=400, detail="Email already registered")

@app.post("/login")
def login(data: LoginModel):
    try:
        user = fb_auth.get_user_by_email(data.username)
        # (Note: Firebase Admin can't verify passwords — see note below)
        token = auth.create_access_token({"sub": user.uid})
        return {"access_token": token, "token_type": "bearer"}
    except fb_auth.UserNotFoundError:
        raise HTTPException(status_code=400, detail="Invalid user")

@app.post("/create-password")
def add_password(entry: PasswordEntry, token: str = Depends(oauth2_scheme)):
    user_id = get_user_id_from_token(token)

    # Generate custom ID
    password_id = str(uuid.uuid4())
    
    password_entry = {
        "password_id": password_id,
        "username": entry.username,
        "game_name": entry.game_name,
        "gmail": entry.gmail,
        "password": entry.password,
        "sony_password": entry.sony_password,
        "amount_spent": entry.amount_spent,
        "user_id": user_id
    }
    print("user_id", user_id)
    # Create the document with the custom ID
    db.collection("passwords").document(password_id).set(password_entry)

    return {
        "message": "Password entry added",
        "password_id": password_id,
        "status": "success"
    }

@app.get("/get-passwords")
def get_passwords(token: str = Depends(oauth2_scheme)):
    user_id = get_user_id_from_token(token)
    entries = db.collection("passwords").where("user_id", "==", user_id).stream()
    return [{**doc.to_dict(), "id": doc.id} for doc in entries]
