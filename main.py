from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Annotated

# --- SECURITY SETUP ---
# This is our secret key. In a real app, this MUST be more complex and kept secret.
SECRET_KEY = "a-very-secret-key-for-our-project"
ALGORITHM = "HS256"

# This handles password hashing (so we don't store plain text passwords)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# This sets up the URL where the frontend will send the username and password
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# --- DUMMY USER DATABASE ---
# For now, our "database" is just this. We will check against this.
# In a real project, this would be a secure database table.
# The password "adminpass" is stored in its hashed form.
fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": "$2b$12$EixZaYVK1e9n2wOPM9TjVuY3bJzC.2G3vI1xMGx741x/yv2wLz/Fu"
    }
}

# --- HELPER FUNCTIONS for security ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        return db[username]

# --- THE LOGIN ENDPOINT ---
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
    # If login is successful, create a token
    access_token_data = {"sub": user["username"]}
    access_token = jwt.encode(access_token_data, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": access_token, "token_type": "bearer"}

# --- OUR NEW, PROTECTED "Hello World" ENDPOINT ---
# Notice the `token: Annotated[str, Depends(oauth2_scheme)]` part.
# This means this endpoint CANNOT be accessed without a valid token.
@app.get("/")
async def read_root(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"Hello": "Authenticated World"}