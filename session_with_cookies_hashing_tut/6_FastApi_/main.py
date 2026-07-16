import os, bcrypt, uvicorn, socket, json, re, asyncio

from fastapi import FastAPI, Form, File, UploadFile, Request, Response, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from starlette.middleware.sessions import SessionMiddleware

from dotenv import load_dotenv, set_key, unset_key
from contextlib import contextmanager
from typing import Optional 
from pydantic import BaseModel, Field, field_validator




# ============ validator BaseModel classes ==============
class UserResponse(BaseModel):
    userName: str  # can not be empty=None
    password: str  # hashed password
    userDescription: Optional[str] = None # Optional means: UI can send None but not empty
    userEmail: str
    age: Optional[int] = None


class UserRequest(BaseModel):
    userName: str = Field(
        min_length=3, 
        max_length=20,
        description="User name must be between 3 and 20 characters.",
    )
    password: str = Field(
        min_length=10, 
        max_length=15
    )
    userDescription: Optional[str] = None
    userEmail: str = Field(
        pattern=r"^[\w.-]+@[\w.-]+\.\w+$",
        description="User email must be a valid email address.",
    )
    age: Optional[int] = Field(
        default=None, ge=18, le=100,
        description="User age must be between 18 and 100.",
    )

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
    


class UserLoginData(BaseModel): 
    userName: str = Field(
        min_length=3, 
        max_length=20,
        description="User name must be between 3 and 20 characters.",
    )
    password: str = Field(
        min_length=10, 
        max_length=15
    )
    @field_validator("password")
    @classmethod
    def check_password(cls, v: str) -> str:
        if (not re.search(r"[a-z]", v) or not re.search(r"[A-Z]", v) or not re.search(r"\d", v) or not re.search(r"[^A-Za-z0-9]", v)):
            raise ValueError("password does not meet complexity requirements")
            # must have : at-least 1 lowercase, 1 uppercase, 1 digit, 1 special character and min-length=10, max-length=15
        return v



# =================== Process Data in Database ===================
async def insertDataToDB(userAllData: dict) -> dict: 
    with open(os.path.join(os.path.abspath("./session_with_cookies_hashing_tut/6_FastApi_"), "database.json"), "r") as f:
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
            "age": userAllData.get("age")
        }

        db_data['ALL_SESSION_ID'].append(user_session_id)
        with open(os.path.join(os.path.abspath("./session_with_cookies_hashing_tut/6_FastApi_"), "database.json"), "w") as f:
            json.dump(db_data, f, indent=4)

        return {
            "message": "User data inserted successfully", 
            "user_session_id": user_session_id, 
            "userName": userAllData["userName"]
        }



async def getDataFromDB(userName: str, password: str) -> dict: # if there are no session -> this Fn used
     # hash user password before storing it in the database 
    pwd_bytes = password.encode("utf-8")[:72]
    with open(os.path.join(os.path.abspath("./session_with_cookies_hashing_tut/6_FastApi_"), "database.json"), "r") as f:
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

            with open(os.path.join(os.path.abspath("./session_with_cookies_hashing_tut/6_FastApi_"), "database.json"), "w") as f:
                json.dump(db_data, f, indent=4)


            return {
                "user_session_id": user_session_id, 
                "userName": userName,
                "password": stored_hashed_password,
                "userDescription": db_data[userName].get("userDescription"),
                "userEmail": db_data[userName]["userEmail"],
                "age": db_data[userName].get("age")
            }




async def getDataFromDB_For_Session(userName: str, sessionId: int) -> dict:
    # get the user data using username and session id
    with open(os.path.join(os.path.abspath("./session_with_cookies_hashing_tut/6_FastApi_"), "database.json"), "r") as f:
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
                "age": db_data[userName].get("age")
            }





async def updateDataInDB(userName: str, user_session_id: int, userAllData: dict) -> dict:
    pass

async def deleteDataFromDB(userName: str, user_session_id: int,) -> dict:
    pass





# =================== FastApi App ========================
my_custom_app = FastAPI(
    title="My Custom App", 
    description="This is a custom FastAPI application.", 
    version="1.0.0"
)


# =================== Add and manage session Middleware ===================
# generate a dummy sectet Key
import secrets
sec_key = secrets.token_hex(16)

my_custom_app.add_middleware(
    SessionMiddleware, 
    secret_key=sec_key, 
    session_cookie="my_session_cookie",
    max_age=60,  # 00 sec
    same_site="lax",  # "strict" or "lax" or "none"
    https_only=False,  # during production , make it True
)



# =================== Add FastApi Routes ===================
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



# login -> first time -> validate user -> set up cookie
# login -> 2nd time -> validate user with cookie
@my_custom_app.post("/login", response_model=UserResponse, status_code=201)
async def user_login(request:Request, userData: Optional[UserLoginData] = None)->dict:

    session_userName = request.session.get("userName")
    sesssion_id = request.session.get("user_session_id")

    if session_userName is not None and sesssion_id is not None:
        dbResp = await getDataFromDB_For_Session(session_userName, sesssion_id)
    else: 
        # if there are no cookes in session --- then login using the provided credentials
        usrNamePass = userData.model_dump() # user request comes from -> Json format 
        # in OAuth2 -> user request comes in 'body'-> data = [....]

        # get the data from database.json
        dbResp = await getDataFromDB(usrNamePass["userName"].replace(" ", "__"), usrNamePass["password"])
        print("Database Response:", dbResp)


        # Now set-up Cookies in session - (username and session id)
        request.session['userName'] = dbResp['userName']
        request.session['user_session_id'] = dbResp['user_session_id']


        # raise HTTPException(status_code=400, detail="User already logged in")
    return dbResp



@my_custom_app.post("/logout", response_model=UserResponse, status_code=201)
async def user_logout(request:Request)->dict:
    request.session.clear() 
    return {
        "message": "logged out",
        "status_code": 201
    }




if __name__ == "__main__": 
    uvicorn.run("main:my_custom_app" , host='127.0.0.1' , port=8786, reload=True, workers=1)
    # workers => number of processes to run
    # seach for http://127.0.0.1:port/docs









