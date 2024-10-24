from Crypto.Util.number import *
from math import lcm
import random


class pailier:
    def __init__(self):
        while True:
            p, q = getPrime(512), getPrime(512)
            if GCD(p*q, (p-1)*(q-1)) == 1:
                break
        self.phi=lcm(p-1,q-1)
        self.n = p * q
        self.g = self.n+1
        self.miu=inverse(self.L(pow(self.g,self.phi,self.n**2)),self.n)

    def L(self,val):
        return (val-1)//self.n
        
    def pubkey(self):
        return (self.n,self.g)

    def encrypt(self,msg):
        r=random.randrange(0,self.n-1)
        gm=pow(self.g,msg,self.n**2)
        rn=pow(r,self.n,self.n**2)
        ct=(gm*rn)%(self.n**2)
        return ct

    def decrypt(self,ct):
        m=self.L(pow(ct,self.phi,self.n**2))%self.n
        m=(m*self.miu)%self.n
        return long_to_bytes(m)
