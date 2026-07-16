# pip install passlib bcrypt shiny

from dotenv import load_dotenv
import bcrypt
import os

load_dotenv()

password = os.getenv("PASSWORD")
print("Before hashing:", password)

pwd_bytes = password.encode("utf-8")[:72]  
# needs to encode the text in "utf-8" first --- 72-byte limit
hashed_password = bcrypt.hashpw(pwd_bytes, bcrypt.gensalt(rounds=12, prefix=b"2b"))  
# 12 rounds of hashing || higher = slower = more secure. Default is 12.
print("After hashing:", hashed_password.decode())
print("After hashing:", hashed_password.decode().encode())


# =========== check the password(varify) ==============
is_valid = bcrypt.checkpw(pwd_bytes, hashed_password)
print("Password is valid:", is_valid)










