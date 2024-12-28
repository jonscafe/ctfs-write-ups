
### Forensic/Manipulate
icmp packet data contains the chars of the flag

![image](https://hackmd.io/_uploads/S1RBHUnBye.png)

![image](https://hackmd.io/_uploads/rkDtB82r1l.png)

```
tshark -r traffic.pcap -Y "icmp" -T fields -e data | xxd -r -p > tes.txt
```

### Forensic/Oh Man
main ref: https://malwarelab.eu/posts/tryhackme-smb-decryption/#method-3-decrypting-smb-with-the-captured-traffic-only

by using protocol hierarcy we know that the mainly used protocol is SMB, and we can saw that there are encrypted SMB3 protocol.

based on the reference we have 3 ways to decrypt the encrypted data. and we use this one.

first we need to know which packet that contains the auth between the client and server

![image](https://hackmd.io/_uploads/Sk1WOwnrkx.png)

we use this commands to dump the data we needed to decrypt the SMB3 packets

```
tshark -n -r wgmy-ohman.pcapng -Y 'ntlmssp.messagetype == 0x00000003' -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain -e ntlmssp.ntlmv2_response.ntproofstr -e ntlmssp.auth.ntresponse > dump.txt
```

```
tshark -n -r wgmy-ohman.pcapng -Y 'ntlmssp.messagetype == 0x00000002' -T fields -e ntlmssp.ntlmserverchallenge > dum
p2.txt
```
tidy it into format that given in the reference

![image](https://hackmd.io/_uploads/SJEhDDhHyg.png)

and then use hashcat to find the correct passphrase
```
hashcat -O -a 0 -m 5600 dump.txt /usr/share/wordlists/rockyou.txt
```

![image](https://hackmd.io/_uploads/HkKaPw3Bkg.png)

after that we can use the passphrase to decrypt the NTLM Packets that we will use to find more data to decrypt the SMB3 packets.

![image](https://hackmd.io/_uploads/rkDuuD2Bke.png)

here, we need to find the session id we need to specify which sessionkey of the SMB we will retrieve. since there are many  attempt we need can choose it by finding which attempt that has sessionId

![image](https://hackmd.io/_uploads/H1KWoDhSyx.png)

this sessionId is used to decrypt the encrypted session key using parameter we've got before and using this script

```
from Crypto.Cipher import ARC4
from Crypto.Hash import MD4, MD5, HMAC

password = 'password<3'
passwordHash = MD4.new(password.encode('utf-16-le')).hexdigest()
username = 'Administrator'
domain = 'DESKTOP-PMNU0JK'
ntProofStr = 'ae62a57caaa5dd94b68def8fb1c192f3'
serverChallenge = '7aaff6ea26301fc3'
sessionKey = '12140eb776cb74a339c9c75b152c52fd'

responseKey = HMAC.new(bytes.fromhex(passwordHash), (username.upper()+domain.upper()).encode('utf-16-le'), MD5).digest()
keyExchangeKey = HMAC.new(responseKey, bytes.fromhex(ntProofStr), MD5).digest()
decryptedSessionKey = ARC4.new(keyExchangeKey).decrypt(bytes.fromhex(sessionKey))
print('Decrypted SMB Session Key is: {}'.format(decryptedSessionKey.hex()))
```
and then we use it with the session key to decrypt the SMB protocol

![image](https://hackmd.io/_uploads/HkVQswhrJg.png)

after we've got the decrypted SMB, we can analyze the data that are exfiltrated. we can saw that it has 5 files that are being transported.

![image](https://hackmd.io/_uploads/SymljvhBke.png)

the nano.exe when i try to find out it seems to be nanodump.exe that usually used to dump LSA. and from this file we've got some hint related to the LSA minidump data.

![image](https://hackmd.io/_uploads/HJ0gldnHJg.png)

by analyzing the .log file it seems to be broken, and we can use this script to restore it

https://github.com/fortra/nanodump/blob/main/scripts/restore_signature

![image](https://hackmd.io/_uploads/SJ2Zg_2Bkl.png)
![image](https://hackmd.io/_uploads/Hyzblu2HJl.png)

### Forensic/Tricky Malware
this chall is a memory forensic. usually when doing this kind of challs we will check the program that has been ran. so we can use volatility plugin such as pslist. here we can saw that there is crypt.exe process that seems to be suspicious

![image](https://hackmd.io/_uploads/B1gwFA3BJg.png)

i crosschecked it by checking the cmdline and noticed that the executable is ran by cmd (specifically by conhost)

![image](https://hackmd.io/_uploads/r1LvKC2H1x.png)

so i dumped it using `vol -f evidence.dmp windows.dumpfiles --virtaddr 0xtheoffsetoftheexe` by filling the offset from the value i got by using windows.filescan and grep "crypt.exe"

after i've got the executable i decompile it using pyinstxtractor and convert the bytecode using pylingual

![image](https://hackmd.io/_uploads/ryOOYAhryx.png)

we can notice that the exe is encrypted some files, i try to find the file but couldnt find anything.

noticed that the key is taken from pastebin raw file, i try to access it and found the flag

the flag is in the pastebin on the decompiled code

![image](https://hackmd.io/_uploads/HyDLtCnSJl.png)
![image](https://hackmd.io/_uploads/B1waFAnSJx.png)

### Forensic/Meow
based on the chall name we know that the file has "unwanted meow".

![image](https://hackmd.io/_uploads/SyRHjUpHkx.png)

so we create a script to clean "meow" from raw data of the file and saved it as jpeg since the header is jpg magic bytes.
```
# Script to process flag.shredded and save as flag.jpg
input_file = "flag.shredded"
output_file = "flag.jpg"

try:
    # Read the raw data from the input file
    with open(input_file, "rb") as file:
        raw_data = file.read()
    
    # Replace occurrences of "meow" with an empty string
    cleaned_data = raw_data.replace(b"meow", b"")
    
    # Save the cleaned data as the output file
    with open(output_file, "wb") as file:
        file.write(cleaned_data)
    
    print(f"Processed file saved as {output_file}")
except FileNotFoundError:
    print(f"Error: {input_file} not found.")
except Exception as e:
    print(f"An error occurred: {e}")
```

after that, we got the files but its still broken

![image](https://hackmd.io/_uploads/BknOiUaS1g.png)

and when analyzing it again, we notice that it still has "meow" junk

![image](https://hackmd.io/_uploads/SycqoIpr1e.png)

so we clean it once more by running the script

![image](https://hackmd.io/_uploads/r1W3jI6BJx.png)

### Misc/Christmas GIFt (Stego)
using frame browser, stegsolve

![image](https://hackmd.io/_uploads/B1lo1DTByl.png)

### Misc/Invisible Ink (Stego)
open gif using stegsolve and found 2 sus frame

![image](https://hackmd.io/_uploads/H1cKIu2ryx.png)

extract both of 2 frame and we can saw that it has the content of the flag.

i saved it into 2 images and then combine it using image combiner in the stagesolve

![image](https://hackmd.io/_uploads/S11_IuhHye.png)

### Misc/The DCM Meta (Stego)

sort the readable strings from the raw data using the given indices

```
# The list of indices provided in the challenge
indices = [25, 10, 0, 3, 17, 19, 23, 27, 4, 13, 20, 8, 24, 21, 31, 15, 7, 29, 6, 1, 9, 30, 22, 5, 28, 18, 26, 11, 2, 14, 16, 12]

# Read the binary file
file_path = 'challenge.dcm'  # Update with the actual file path if needed
with open(file_path, 'rb') as file:
    file_content = file.read()

# Decode the file content to extract readable ASCII characters
readable_data = ''.join(chr(byte) for byte in file_content if 32 <= byte <= 126)

# Remove 'WGMY' from the readable data
cleaned_data = readable_data.replace("wgmy", "")

# Extract characters from the cleaned data using the indices
flag = ''.join(cleaned_data[i] for i in indices)

# Wrap the flag in wgmy{} as per the challenge instructions
formatted_flag = f"WGMY{{{flag}}}"

# Print the flag
print(formatted_flag)

└─$ python3 1.py
wgmy{51fadeb6cc77504db336850d53623177}
```

### Crypto/Credentials
![image](https://hackmd.io/_uploads/BkCeWwaByl.png)

rot bruteforce

![image](https://hackmd.io/_uploads/ryu-ZPaH1x.png)

### Game Hacking/World 1
this game is packed with Enigma Virtual Box so we will use evbunpack to unpack it

![image](https://hackmd.io/_uploads/SJOpCPTByg.png)

the resulted unpack data contains some json that we can manipulate to hack the game. here i manipulate the weapon damage and armor defense as 9999 so i'll be in god mode

![image](https://hackmd.io/_uploads/Sk9hCPTSyg.png)

everytime we've defeated the boss we will got the flags.

![image](https://hackmd.io/_uploads/SyDjCPpB1l.png)

![image](https://hackmd.io/_uploads/S19i0vpHkg.png)

![image](https://hackmd.io/_uploads/By3sRDaSkl.png)

after defeating final boss, this pw is the same with the one we got from Map006.json (but its on ascii code)

![image](https://hackmd.io/_uploads/HkTzJ_TSyg.png)

got pw from viewing Map006.json data

![image](https://hackmd.io/_uploads/BJool_6SJg.png)

we will submit the pw to the orb that we interact in the final map and we will got flag 5 item that is a qr

![image](https://hackmd.io/_uploads/HyE4dYTrJe.png)

got flag 5 with this qr

![image](https://hackmd.io/_uploads/SkMCluTByx.png)
`3fcaac2}`
part 4 is hidden in the lava map, unlocked after defeating the boss
![image](https://hackmd.io/_uploads/S1w3Y_6Hkl.png)

`43effd`
full flag: `wgmy{5ce7d7a7140ebabf5cd43effd3fcaac2}`
