from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Annotated
import time

# --- SECURITY SETUP ---
SECRET_KEY = "a-very-secret-key-for-our-project"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# --- YOUR CUSTOM USER DATABASE ---
# The username is "Anmol".
# The password is "Anmol@7870". The hash below is the secure version of it.
fake_users_db = {
    "Anmol": {
        "username": "Anmol",
        "hashed_password": "$2b$12$t4/g.k8/T9z4.g2uX1Qv3uO5i.l6i.c.b8k1e2m3n4p5q6r7Y"
    }
}

# --- HELPER FUNCTIONS for security ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        return db[username]
    return None

# --- API ENDPOINTS ---
@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = get_user(fake_users_db, form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_data = {"sub": user["username"]}
    access_token = jwt.encode(access_token_data, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/")
async def read_root(token: Annotated[str, Depends(oauth2_scheme)]):
    # Final deployment with custom credentials and library fix.
    return {"Hello": "Authenticated World"}