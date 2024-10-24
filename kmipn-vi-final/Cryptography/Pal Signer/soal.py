from Crypto.Util.number import *
from pailier import *
from secret import flag
import random




def encrypt_flag():
    flag_arr=[ord(i) for i in flag]
    for i in range(len(flag)):
        flag_arr[i]*=random.randrange(0,random.randrange(2**128))
    return flag_arr

cipher=pailier()
while True:
    print("What u want to do?")
    print("1. sign a message")
    print("2. get flag")
    print("3. exit")
    inp=int(input("> "))
    if inp==1:
        print("Enter your messsage (hex)")
        inp=input("> ")
        inp=int(inp,16)
        if (inp>0 and inp<cipher.n**2) and (long_to_bytes(inp)!=b"bwang flagnya dong"):
            print('your signature :','{0:x}'.format(cipher.encrypt(inp)))
        else:
            print("Okay... hengker")
            exit()
    elif inp==2:
        print("Enter the correct signature (hex)")
        inp=input("> ")
        inp=int(inp,16)
        if cipher.decrypt(inp)==b"bwang flagnya dong":
            print("Here's your flag xixixixi")
            print(encrypt_flag())
        else:
            print("Okay... hengker")
            exit()
    else:
        exit()