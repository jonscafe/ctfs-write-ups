## BackdoorCTF 2024 - InfosecIITR - Forensic

Collaboration of daffainfo - k.eii - k3ng


### Cursed Credential

Given cred firefox. Encrypted with master password, cant use firefox_decryptor

Found out that the master password is used to create encryption variable for key4.db. So we need to find the master password by bruteforcing it.

https://fossies.org/linux/hashcat/tools/mozilla2hashcat.py 

Use hashcat to bruteforce
![image](https://github.com/user-attachments/assets/ea635848-4689-4937-ab77-a0316d27572d)

### Torrent Tempest

Got pcap with bittorrent protocol, try to dissect the packet to get flag.zip
```
## credit to k3ng
import pyshark
from binascii import unhexlify

packets = pyshark.FileCapture("torrent.pcap")
res = []

for packet in packets:
    if "bittorrent" in packet and packet.ip.src == "10.0.0.1":
        try:
            data = packet["bittorrent"].continuous_data.replace(":", "")
            data = unhexlify(data)[13:]
            print(data[:20])
            if data not in res:
                res.append(data)
        except:
            pass

final = b"".join(res)
with open("flag.zip", "wb") as f:
    f.write(final)
```

Flag.zip contain secret.wav and key.txt
![image](https://github.com/user-attachments/assets/c5369c2d-a319-4c71-aa1c-1c0742d20fe2)

The content of key .txt is a key for stego-ed wav file. We can use deepsound
![image](https://github.com/user-attachments/assets/66e2c3d5-5d0c-4fcd-95cf-5a13a2565e15)
![image](https://github.com/user-attachments/assets/bfedcd60-f19d-460b-a814-07d370c8e527)

### My boss's boss's boss? 

There is a hidden obj in the pdf
![image](https://github.com/user-attachments/assets/d68ed589-79a5-4de6-967b-022f796faf1c)

It turnsout xoring certain bytes will get us a zip file (using xor 57 got from the obj)
```
# Original byte data (same as before)
byte_data = [
    [7, 28, 84, 83, 67, 87, 94, 87, 95, 87, 207, 42, 195, 14, 239, 93, 181, 65, 243, 87, 87, 87, 202, 87, 87, 87, 92, 87, 75, 87, 49, 59, 54, 48, 121, 35, 54, 37, 121, 48, 45, 2, 3, 94, 87, 84, 207, 20, 50, 48, 207, 20, 50, 48, 34, 47, 92, 87, 86, 83, 191, 84, 87, 87, 83, 191, 84, 87, 87, 42],
    [107, 178, 250, 164, 219, 128, 205, 238, 20, 73, 15, 210, 123, 107, 23, 71, 205, 82, 247, 2, 208, 43, 56, 140, 97, 47, 99, 60, 217, 219, 42, 57, 252, 177, 167, 32, 34, 3, 43, 213, 209, 123, 132, 205, 141, 27, 178, 214, 170, 128, 64, 175, 24, 96, 21, 213, 177, 143, 246, 207, 15, 96, 65, 236, 170, 244, 89, 70, 23, 39],
    [128, 4, 246, 153, 196, 114, 186, 181, 48, 201, 224, 175, 90, 187, 127, 83, 174, 24, 19, 118, 96, 215, 172, 179, 118, 146, 237, 41, 49, 72, 217, 131, 210, 242, 112, 253, 81, 71, 210, 153, 239, 89, 121, 198, 173, 129, 124, 1, 56, 51, 209, 180, 39, 24, 230, 189, 15, 143, 123, 222, 187, 25, 175, 8, 191, 240, 22, 32, 86, 8],
    [253, 150, 241, 219, 166, 211, 115, 189, 88, 42, 45, 152, 215, 2, 112, 4, 45, 190, 123, 40, 219, 124, 184, 7, 28, 80, 95, 239, 93, 181, 65, 243, 87, 87, 87, 202, 87, 87, 87, 7, 28, 86, 85, 73, 84, 67, 87, 94, 87, 95, 87, 207, 42, 195, 14, 239, 93, 181, 65, 243, 87, 87, 87, 202, 87, 87, 87, 92, 87, 79],
    [87, 87, 87, 87, 87, 87, 87, 87, 87, 227, 214, 87, 87, 87, 87, 49, 59, 54, 48, 121, 35, 54, 37, 121, 48, 45, 2, 3, 82, 87, 84, 207, 20, 50, 48, 34, 47, 92, 87, 86, 83, 191, 84, 87, 87, 83, 191, 84, 87, 87, 7, 28, 82, 81, 87, 87, 87, 87, 86, 87, 86, 87, 6, 87, 87, 87, 174, 87, 87, 87, 87, 87]
]


import zipfile
import os

# XOR each byte with 57
def xor_with_57(byte_array):
    return [byte ^ 57 for byte in byte_array]

# Process each byte array, XOR the data
processed_data = [xor_with_57(data) for data in byte_data]
# Write each processed result (in byte form) to a file in a zip archive
zip_file_path = 'xored_data.zip'

with zipfile.ZipFile(zip_file_path, 'w') as zipf:
    for i, content in enumerate(processed_data):
        file_name = f'file_{i+1}.bin'
        with open(file_name, 'wb') as f:
            f.write(bytes(content))  # Save byte data directly
        zipf.write(file_name)
        os.remove(file_name)  # Remove the temporary file after adding it to the zip
zip_file_path
```

The resulting zip is passworded, we can use hashcat to brute it
![image](https://github.com/user-attachments/assets/55cf6b37-c234-4758-b72f-2f95d3b615d1)

