from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Annotated
import time

# --- SECURITY SETUP ---
# This is our secret key for creating tokens.
SECRET_KEY = "a-very-secret-key-for-our-project"
ALGORITHM = "HS256"

# This is the tool for hashing and verifying passwords.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# This tells FastAPI where the login URL is.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Create our main application object.
app = FastAPI()

# --- OUR USER DATABASE ---
# This dictionary acts as our database of users.
# The username is "admin".
# The password is "password". The long string is the secure, "hashed" version of "password".
fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": "$2b$12$EixZaYVK1e9n2wOPM9TjVuY3bJzC.2G3vI1xMGx741x/yv2wLz/Fu"
    }
}

# --- HELPER FUNCTIONS (Tools for our security system) ---

# This function checks if a plain password (like "password") matches a hashed one.
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# This function looks up a user in our fake database.
def get_user(db, username: str):
    if username in db:
        return db[username]
    return None

# --- API ENDPOINTS (The URLs our app will talk to) ---

# This is the LOGIN endpoint. It's available at the URL "/token".
@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    # Look up the user from the form data.
    user = get_user(fake_users_db, form_data.username)
    
    # If the user doesn't exist or the password is wrong, reject the login.
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # If login is successful, create a secret token.
    access_token_data = {"sub": user["username"]}
    access_token = jwt.encode(access_token_data, SECRET_KEY, algorithm=ALGORITHM)
    
    # Send the token back to the user.
    return {"access_token": access_token, "token_type": "bearer"}


# This is our PROTECTED endpoint. It's available at the main URL "/".
# It requires a valid token to be accessed.
@app.get("/")
async def read_root(token: Annotated[str, Depends(oauth2_scheme)]):
    # This comment includes the current time to force a new deployment.
    # Deploy time: Friday, 2 August 2025 04:10:00 AM
    return {"Hello": "Authenticated World"}