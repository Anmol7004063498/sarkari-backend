from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt
from typing import Annotated

# --- SECURITY SETUP (Simplified) ---
SECRET_KEY = "a-very-secret-key-for-our-project"
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# --- SIMPLIFIED USER DATABASE ---
# We are storing the password directly for this test.
fake_users_db = {
    "admin": {
        "username": "admin",
        "password": "password"  # The password is in plain text
    }
}

# --- HELPER FUNCTION (Simplified) ---
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
    
    # We now compare the plain text passwords directly.
    if not user or form_data.password != user["password"]:
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
    return {"Hello": "Authenticated World"}