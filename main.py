from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt
from typing import Annotated
from fastapi.middleware.cors import CORSMiddleware # Import the CORS middleware

# --- SECURITY SETUP (Simplified) ---
SECRET_KEY = "a-very-secret-key-for-our-project"
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# --- CORS MIDDLEWARE SETUP ---
# This is the new section that fixes the browser error.
# It tells our backend to trust our frontend.
origins = [
    "http://localhost:3000", # The address of our local React app
    # In the future, we will add our live frontend URL here too.
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # Allow all methods (GET, POST, etc.)
    allow_headers=["*"], # Allow all headers
)

# --- SIMPLIFIED USER DATABASE ---
fake_users_db = {
    "admin": {
        "username": "admin",
        "password": "password"
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