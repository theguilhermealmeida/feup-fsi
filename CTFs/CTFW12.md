# Week 12: CTF

## Goal

Understanding insecure uses of RSA

### Challenge 1

In this challenge the goal was to be able to decrypt a message encrypted with the RSA algorithm by knowing the public key and the two prime numbers that were used to create the key. This challenge proved that the security of the RSA algorithm is based on the fact that it is very complicated to factor prime numbers, so their secrecy makes this algorithm very secure.

We first started by founding the p and q prime numbers. We knew that this numbers were close to 2^512 and 2^513 so we used <https://www.wolframalpha.com/input?i=NextPrime+2%5E512> and <https://www.wolframalpha.com/input?i=NextPrime+2%5E513> to find those out.

```python
p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171 # next prime 2**512
q = 26815615859885194199148049996411692254958731641184786755447122887443528060147093953603748596333806855380063716372972101707507765623893139892867298012168351 # next prime 2**513
```

Using p and q we can discover the private key (d) and compromise the RSA algorithm. We started by calculating the totient(t) of n=pq. Because p and q are prime, t = (p-1)(q-1). Now we know that d is the modular multiplicative inverse of e mod t.

We made a helper function to calculate modular inverse using the extended euclidian algorithm:

```python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
```

And we calculated d :

```python
d = modinv(e, (p-1)*(q-1))
```

Now with the private and public key we can decrypt and encrypt any message so we decrypted the flag:

```python
from binascii import hexlify, unhexlify

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171 # next prime 2**512
q = 26815615859885194199148049996411692254958731641184786755447122887443528060147093953603748596333806855380063716372972101707507765623893139892867298012168351 # next prime 2**513
n = p*q

e = int(0x10001) # a constant

d = modinv(e, (p-1)*(q-1))

enc_flag = b"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a4e88ac1f04070e6f4b14e60575082a63ce53c2e95827b4c66d5741646bcb5aa98edd8023ad33057e9a8d56cf33362f60468b5d3da590747d7862ca8b132220ad3bdc02e0c52c68afdff3d1938f4314ef1fdc1c7ff91e9f46ad19e877912b38f2d5ddbd7ef47f8646f4b79e067579e7b50f9d4c4beca1a0665c890d2edfd6fc4"

def enc(x):
    int_x = int.from_bytes(x, "big")
    y = pow(int_x,e,n)
    return hexlify(y.to_bytes(256, 'big'))

def dec(y):
    int_y = int.from_bytes(unhexlify(y), "big")
    x = pow(int_y,d,n)
    return x.to_bytes(256, 'big')

y = dec(enc_flag)
print(y.decode())
```

And we got:

```bash
tiagobarbosa05@MBP-de-Tiago-2 Documents % python3 test.py
flag{fee20ff3aab25b9bc8d33db101375477}
```

### Challenge 2

In this challenge we didn't knew the prime numbers that were used to build the keys but we had the same message encrypted with the same n but different e's so we had :

```text
c1 = m^e1 mod n
c2 = m^e2 mod n
```

This equation is solvable and we can get m without even knowing the private key.

We know that if gcd(e1,e2)=1 then ∃𝑎,𝑏∈ℤ:e1⋅a+e2⋅b=1 and a and b can be found with the extended euclidian algorithm. Because e1: 0x10001 and e2: 0x10003, gcd(e1,e2)=1 so the above is possible in this situation.

After getting a and b we know that m = c1^a⋅c2^b mod n so to get m we just need to find a and b. Because one of a or b will be negative (Let b be the negative one) and that will bring problems in that equation we can use the following :

```text
We can get i that is the modular multiplicative inverse of c2 mod n.
And know we know that m = c1^a⋅i^-b mod n.
```

So we put this in the python file and calculated i and then m and decoded the message and got the original flag:

```python
from binascii import hexlify, unhexlify
import sys

sys.setrecursionlimit(1500)
 
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

enc_flag1 = b"9e9abe098260845ae4858d2795803bcb4e164063016d05e4650d5b1b2445b862d31b97c73b01f3b5394c67c1082bed610f8a9916913f0465119cd2ac057d65ed0a692621ab024fe1378a531149b16f3ea4d01549f051ffc2b1fbf7d85bfe1a98bc7cbeb451fc4e47575702fbf602f63694c8f930ebda5b8aa3d381feae1f9d7a0af5319afe9b78d52542f4d9e70b4a98e97bc0b8a3ec86bd712820014aa5e0e5d09b7b7a7180afb1b24548d313803d297f46ddb6189470b03c77b02531339a8c8bab28b58dd1a1dbc097c179f777c1c96a0f30ae83e2704283ce6df1cad6d0f5ca4b11903e00f9f1f1f95d1507062f8f24192e7587e66d9ce7863583395afe8e"
enc_flag2 = b"0b58a8f18d059852018786310df144a591ee8ade23c8aacb20ea3822b4e81b15978a337813cb6bc9369621969e99a8f047a4c6b0685f933d78a7e662bb70fec1b7fc967ba571d2f9622e88146a50aa496a2078821a8d653fb7219e3dc3a09db6e134a1398dcf84bd461a172953d884c2b83b713925e08ae08c31820f77b7720d6e29fbecf24599b46d2b73c9abd6e6ecd5ad2e2f5cb8a35d1c140b4dcfc3d2b1c253f53f09e3b6a3a8fce8b759a4a754a3636108cd11218ec7541380d1c4238392a1979408dc9bc1af2c0800edaf06f8a20c790c305a89d012ff1c080dafd27b673f3a558243525befba7b64f05707dd047e290788babebc1eacff2d96466cb6"
e1 = int(0x10001)
e2 = int(0x10003)
c1=int.from_bytes(unhexlify(enc_flag1), "big")
c2=int.from_bytes(unhexlify(enc_flag2), "big")
n = 29802384007335836114060790946940172263849688074203847205679161119246740969024691447256543750864846273960708438254311566283952628484424015493681621963467820718118574987867439608763479491101507201581057223558989005313208698460317488564288291082719699829753178633499407801126495589784600255076069467634364857018709745459288982060955372620312140134052685549203294828798700414465539743217609556452039466944664983781342587551185679334642222972770876019643835909446132146455764152958176465019970075319062952372134839912555603753959250424342115581031979523075376134933803222122260987279941806379954414425556495125737356327411

not_important, a, b = egcd(e1,e2)
i = modinv(c2,n)
m1 =c1**a
m2 =i**(-b)
m = (m1 * m2) % n
print(m.to_bytes(256,'big').decode())
```

And we got:

```bash
tiagobarbosa05@MBP-de-Tiago-2 Downloads % python3 template.py
flag{a5aa234abfd62741733679cc1af03d6d}
```

Note: To discover this attack we based on this thread <https://crypto.stackexchange.com/questions/1614/rsa-cracking-the-same-message-is-sent-to-two-different-people-problem> and adapted it to our situation.
