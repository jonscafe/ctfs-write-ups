from rc4 import *
from secret import flag
import os

key=os.urandom(32)
while True:
    print("What you want to do?")
    print("1. Encrypt message")
    print("2. Encrypt flag")
    print("3. Exit")
    inp=int(input("> "))
    if(inp==1):
        print("Enter your message")
        m=input("> ")
        print(f"encrypted : {encrypt(m,key)}")
    elif(inp==2):
        print(f"encrypted : {encrypt(flag,key)}")
    else:
        exit()