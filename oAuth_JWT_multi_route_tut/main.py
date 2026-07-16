# oAuth_JWT_multi_route_tut > main.py

import os, re, json, uvicorn, bcrypt, jwt

from fastapi import FastAPI, Form , File , UploadFile, Request, Response, Depends, HTTPException, APIRouter, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from pydantic import BaseModel, Field, field_validator
from typing import Annotated, Optional, Literal
from dotenv import load_dotenv, set_key, unset_key

from datetime import datetime, timedelta, timezone




# =================== Process Data in Database ===================
async def insertDataToDB(userAllData: dict) -> dict: 
    with open(os.path.join(os.path.abspath("./oAuth_JWT_multi_route_tut"), "database.json"), "r") as f:
        db_data = json.load(f)

    # Check if the userName already exists
    if userAllData['userName'] in db_data and userAllData['userName'] != "ALL_USER_ID":
        raise HTTPException(status_code=400, detail="User already exists")
    

    else: 
        user_session_id = -1 # session has not yet set


        # hash user password before storing it in the database
        pwd_bytes = userAllData["password"].encode("utf-8")[:72]
        hashed_password = bcrypt.hashpw(pwd_bytes, bcrypt.gensalt(rounds=12, prefix=b"2b"))
        userAllData["password"] = hashed_password.decode()
        
        db_data[userAllData["userName"]] = {
            "user_session_id": user_session_id,
            "password": userAllData["password"],
            "userDescription": userAllData.get("userDescription"),
            "userEmail": userAllData["userEmail"],
            "age": userAllData.get("age"),
            "gender": userAllData.get("gender")
        }

        db_data['ALL_SESSION_ID'].append(user_session_id)
        with open(os.path.join(os.path.abspath("./oAuth_JWT_multi_route_tut"), "database.json"), "w") as f:
            json.dump(db_data, f, indent=4)

        return {
            "message": "User data inserted successfully", 
            "user_session_id": user_session_id, 
            "userName": userAllData["userName"]
        }
    



async def getDataFromDB(userName: str, password: str) -> dict: # if there are no session -> this Fn used
     # hash user password before storing it in the database 
    pwd_bytes = password.encode("utf-8")[:72]
    with open(os.path.join(os.path.abspath("./oAuth_JWT_multi_route_tut"), "database.json"), "r") as f:
        db_data = json.load(f)


    if userName not in db_data.keys():
        raise HTTPException(status_code=404, detail="User not yet registered")
    
    else: 
        stored_hashed_password = db_data[userName]["password"]
        if not bcrypt.checkpw(pwd_bytes, stored_hashed_password.encode()):
            raise HTTPException(status_code=401, detail="Invalid password")
        
        else:
            # now create a session if for user 
            existing_sess_ids = set(db_data['ALL_SESSION_ID'])
            user_session_id = -1
            while user_session_id in existing_sess_ids: 
                # because of set the search is faster O(n^2) -> O(n) || set search time is O(1)
                user_session_id += 1

            
            # update 'user_session_id' in database
            db_data[userName]['user_session_id'] = user_session_id
            db_data['ALL_SESSION_ID'].append(user_session_id)

            with open(os.path.join(os.path.abspath("./oAuth_JWT_multi_route_tut"), "database.json"), "w") as f:
                json.dump(db_data, f, indent=4)


            return {
                "user_session_id": user_session_id, 
                "userName": userName,
                "password": stored_hashed_password,
                "userDescription": db_data[userName].get("userDescription"),
                "userEmail": db_data[userName]["userEmail"],
                "age": db_data[userName].get("age"),
                "gender": db_data.get("gender")
            }
        




async def getDataFromDB_For_jwt(userName: str) -> dict:
    # get the user data using username and session id
    with open(os.path.join(os.path.abspath("./oAuth_JWT_multi_route_tut"), "database.json"), "r") as f:
        db_data = json.load(f)

    if userName not in db_data.keys():
        raise HTTPException(status_code=404, detail="User not yet registered")
    
    else: 
        return {
                "user_session_id":  db_data[userName]["user_session_id"], 
                "userName": userName,
                "password": db_data[userName]["password"],
                "userDescription": db_data[userName].get("userDescription"),
                "userEmail": db_data[userName]["userEmail"],
                "age": db_data[userName].get("age"),
                "gender": db_data.get("gender")
            }




# ==================================== FastApi helper Fns ====================================
class UserRequest(BaseModel):
    userName: str = Field(
        min_length=3,
        max_length=20,
        description="User name must be between 3 and 20 characters.",
    )
    password: str = Field(min_length=10, max_length=15)
    userDescription: Optional[str] = None
    userEmail: str = Field(
        pattern=r"^[\w.-]+@[\w.-]+\.\w+$",
        description="User email must be a valid email address.",
    )
    age: Optional[int] = Field(
        default=None,
        ge=18,
        le=100,
        description="User age must be between 18 and 100.",
    )
    gender: Literal["Male", "Female"] | None =  None

    @field_validator("password")
    @classmethod
    def check_password(cls, v: str) -> str:
        if not re.search(r"[a-z]", v):
            raise ValueError("must contain a lowercase letter")
        if not re.search(r"[A-Z]", v):
            raise ValueError("must contain an uppercase letter")
        if not re.search(r"\d", v):
            raise ValueError("must contain a digit")
        if not re.search(r"[^A-Za-z0-9]", v):
            raise ValueError("must contain a special character")
        return v



class UserResponse(BaseModel):
    userName: str
    userDescription: Optional[str] = None
    userEmail: str
    age: Optional[int] = None
    gender: Literal["Male", "Female"] | None =  None





# ==================================== FastAPI App ====================================
my_custom_app = FastAPI(
    title="My Custom App",
    description="FastAPI + OAuth2 + JWT",
    version="2.0.0",
)


 
# ==================================== JWT ====================================
# generte a dummy sectet key
import secrets
JWT_DUMMY_SECRET_KEY  = secrets.token_hex(16)
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")





# ==================================== create routes ====================================
@my_custom_app.get("/")
async def root():
    return {"message": "Hello World"}


@my_custom_app.post("/signup", status_code=201)
async def my_signup(userData: UserRequest)->dict: 
    usrInfo = userData.model_dump() 
    usrInfo['userName'] = usrInfo['userName'].replace(" ", "__")

    # insert the data to database.json
    dbResp = await insertDataToDB(usrInfo)
    print("Database Response:", dbResp)

    return {
        "message": "User data inserted successfully", 
        "user_session_id": dbResp["user_session_id"], 
        "userName": dbResp["userName"]
    }




# ========== 1st time login -> create and send the token to frontend -> frontend save it =============
# OAuth2 password bearer path : OAuth2PasswordBearer -> /login
@my_custom_app.post("/login")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> dict:
    userName = form_data.username.replace(" ", "__")
    password = form_data.password


    # varify the user using atanase and hashing
    dbResp = await getDataFromDB(userName, password) 
    print("Database Response:", dbResp)


    # now create a access token for the first login
    now = datetime.now(timezone.utc)
    payload = {
        "sub": userName,
        "iat": datetime.now(timezone.utc), # curent time 
        "exp": now + timedelta(minutes=JWT_EXPIRE_MINUTES), # when the token will expire
    }
    token = jwt.encode(payload, JWT_DUMMY_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}





# ===== 2nd time login -> frontend send token -> backend validate it and give access ========
async def validate_user_identity_using_token(token: Annotated[str, oauth2_scheme]) -> UserResponse: 
    # annotated taken the token -> sends to oauth2_scheme -> oauth2_scheme returns a str
    try: 
        jwt_token_payload = jwt.decode(token, JWT_DUMMY_SECRET_KEY, algorithms=JWT_ALGORITHM)
    except jwt.ExpiredSignatureError: 
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired, please login again",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError: 
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    print(jwt_token_payload)
    userName = jwt_token_payload.get("sub")

    # if username is not in jwt token
    if userName is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # if token username is not valid
    record_for_DB = await getDataFromDB_For_jwt(userName)
    if record_for_DB is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


    # if all fine then return
    return UserResponse(
        userName = userName,
        userDescription = record_for_DB.get("userDescription"),
        userEmail = record_for_DB["userEmail"],
        age = record_for_DB.get("age"),
        gender = record_for_DB.get("gender")
    )




@my_custom_app.get("/users/me")
async def read_users_2nd_time(current_user: Annotated[UserResponse, Depends(validate_user_identity_using_token)]) -> UserResponse:
    return current_user


@my_custom_app.post("/logout")
async def logout(current_user: Annotated[UserResponse, Depends(validate_user_identity_using_token)]) -> UserResponse:
    # JWT is stateless -> so you can remove anything like session
    # but you can send something  that tells front-end to delete token
    return {"message": "Logged out. Please discard your token on the client side."}




if __name__ == "__main__":
    uvicorn.run("main:my_custom_app", host="127.0.0.1", port=8786, reload=True, workers=1)








