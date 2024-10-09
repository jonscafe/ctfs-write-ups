import secret
import array
import os
from Crypto.Util.number import isPrime, bytes_to_long
from wrath import WRATH

banner = r"""
 _______  _______  _______  _          _______                      _______  _______ _________         
(  ____ \(  ____ \(  ____ \( \        (       )|\     /|  |\     /|(  ____ )(  ___  )\__   __/|\     /|
| (    \/| (    \/| (    \/| (        | () () |( \   / )  | )   ( || (    )|| (   ) |   ) (   | )   ( |
| (__    | (__    | (__    | |        | || || | \ (_) /   | | _ | || (____)|| (___) |   | |   | (___) |
|  __)   |  __)   |  __)   | |        | |(_)| |  \   /    | |( )| ||     __)|  ___  |   | |   |  ___  |
| (      | (      | (      | |        | |   | |   ) (     | || || || (\ (   | (   ) |   | |   | (   ) |
| )      | (____/\| (____/\| (____/\  | )   ( |   | |     | () () || ) \ \__| )   ( |   | |   | )   ( |
|/       (_______/(_______/(_______/  |/     \|   \_/     (_______)|/   \__/|/     \|   )_(   |/     \|
                                                                                                       
"""

menu = r"""
==PART 1==
[1] Get Flag
[2] Decrypt Flag
[3] Encrypt Message

==PART 2==
[4] Get Flag
[5] Get Hint

==PART 3==
[6] Get Flag
[7] Encrypt Message
[8] Quit
"""

class RandomLCG :
    def __init__(self, randomness) :
        self.state = secret.seed
        self.x = secret.x
        self.y = secret.y
        self.z = secret.z
        self.randomness = randomness
    
    def next(self) :
        self.state = ((self.state * self.x) + self.y) % self.z
        return self.state + self.randomness

def generatePrime(generator) :
    primes = []
    hints = []
    counter = 0
    
    while len(primes) < 10 :
        candidate = generator.next()
        counter += 1
        
        if len(hints) < 10  and counter > 5 :
            hints.append(candidate)
        
        if isPrime(candidate) :
            primes.append(candidate)
    
    return primes, hints

def RSA_encrypt(plaintext, primes) :
    n = 1
    for prime in primes :
        n *= prime
    
    return pow(bytes_to_long(plaintext.encode()), 65537, n)

def WRATH_encrypt(plaintext, key) :
    nop = lambda *x: None
    generator = WRATH(key)
    generator.sub_bytes = nop
    ciphertext = generator.encrypt(plaintext)
    return (ciphertext << pow(2, 10)) + (ciphertext >> pow(2, 5)) + 1

def rot(x):
    return ((x<<5) | (x>>3)) & 0xff

def gBox(a, b, mode):
    return rot((a + b + mode) & 0xff)

def fBox(x):
    t0 = (x[2] ^ x[3])
    y1 = gBox(x[0] ^ x[1], t0, 1)
    y0 = gBox(x[0], y1, 0)
    y2 = gBox(y1, t0, 0)
    y3 = gBox(y2, x[3], 1)
    return array.array('B', [y0, y1, y2, y3])

def list_xor(l1, l2) :
    return list(map(lambda x: x[0] ^ x[1], zip(l1, l2)))

def encrypt(plaintext, subkeys) :
    pt_left = plaintext[0:4]
    pt_right = plaintext[4:]
    left = list_xor(pt_left, subkeys[4])
    right = list_xor(pt_right, subkeys[5])
    R2L = list_xor(left, right)
    R2R = list_xor(left, fBox(list_xor(R2L, subkeys[0])))
    R3L = R2R
    R3R = list_xor(R2L, fBox(list_xor(R2R, subkeys[1])))
    R4L = R3R
    R4R = list_xor(R3L, fBox(list_xor(R3R, subkeys[2])))
    ct_left = list_xor(R4L, fBox(list_xor(R4R, subkeys[3])))
    ct_right = list_xor(ct_left, R4R)
    return ct_left + ct_right

def decrypt(ciphertext, subkeys) :
    ct_left = ciphertext[0:4]
    ct_right = ciphertext[4:]
    R4R = list_xor(ct_left, ct_right)
    R4L = list_xor(ct_left, fBox(list_xor(R4R, subkeys[3])))
    R3R = R4L
    R3L = list_xor(R4R, fBox(list_xor(R3R, subkeys[2])))
    R2R = R3L
    R2L = list_xor(R3R, fBox(list_xor(R2R, subkeys[1])))
    left = list_xor(R2R, fBox(list_xor(R2L, subkeys[0])))
    right = list_xor(left, R2L)
    pt_left = list_xor(left, subkeys[4])
    pt_right = list_xor(right, subkeys[5])
    return pt_left + pt_right

def generateKeys() :
    subkeys = []
    for x in range(6) :
        subkeys.append(array.array("B", os.urandom(4)))
    return subkeys

def challenge_prep() :
    global FLAG_PART_1_LEFT, FLAG_PART_1_RIGHT, HINT_PART_2, FLAG_PART_1, FLAG_PART_2, FLAG_PART_3, KEYS, KEYS2, is_admin
    
    is_admin = False
    FLAG = secret.flag
    assert len(FLAG) == 88
    KEYS = generateKeys()
    
    FLAG_PART_1_LEFT = encrypt(FLAG[0:8].encode(), KEYS)
    FLAG_PART_1_RIGHT = encrypt(FLAG[8:16].encode(), KEYS)
    FLAG_PART_1 = FLAG_PART_1_LEFT + FLAG_PART_1_RIGHT
    
    GENERATOR = RandomLCG(int(''.join(map(str, FLAG_PART_1))))
    primes, hints = generatePrime(GENERATOR)
    FLAG_PART_2 = RSA_encrypt(FLAG[16:72], primes)
    HINT_PART_2 = hints
    
    KEYS2 = int(os.urandom(16).hex(), 16)
    FLAG_PART_3 = WRATH_encrypt(bytes_to_long(FLAG[72:].encode()), KEYS2)
    
def challenge() :
    print(banner)
    print(menu)
    
    while True :
        try :
            user_input = int(input("> "))
        except ValueError :
            print("Invalid input\n")
            continue
        
        if user_input == 1 :
            print(f"Flag part 1: {FLAG_PART_1}\n")
        
        elif user_input == 2 :
            FLAG_LEFT_RECOVERED = decrypt(FLAG_PART_1_LEFT, KEYS)
            FLAG_RIGHT_RECOVERED = decrypt(FLAG_PART_1_RIGHT, KEYS)
            if (is_admin==True) :
                print(FLAG_LEFT_RECOVERED + FLAG_RIGHT_RECOVERED)
            else :
                print(f"This function is not working right now. Sorry for the inconvenience.\n")
        
        elif user_input == 3 :
            msg_input = input("Enter your message: ")
            if (len(msg_input) != 16) :
                print("Invalid message length\n")
                continue
            enc_msg = encrypt(bytes.fromhex(msg_input), KEYS)
            print(f"Encrypted message: {enc_msg}\n")
            
        elif user_input == 4 :
            print(f"Flag part 2: {FLAG_PART_2}\n")
        
        elif user_input == 5 :
            print(f"Hint: {HINT_PART_2}\n")
        
        elif user_input == 6 :
            print(f"Flag part 3: {FLAG_PART_3}\n")
            
        elif user_input == 7 :
            msg_input = input("Enter your message: ")
            enc_msg = WRATH_encrypt(bytes_to_long(msg_input.encode()), KEYS2)
            print(f"Encrypted message: {enc_msg}\n")
            
        elif user_input == 8 :
            print(f"Quitting...\n")
            print(banner)
            exit()
        
        else :
            print("Invalid input\n")

if __name__ == "__main__" :
    challenge_prep()
    challenge()