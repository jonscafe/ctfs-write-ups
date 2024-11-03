## <a name="_kghzxlaxs3t9"></a>**WaniCTF 2024 - All Forensic Write Up**

- Author: k.eii
- 6/6 Solved

---

### <a name="_h4uigo9fscm7"></a>**for-tiny**

![image](https://hackmd.io/_uploads/Sybnc5SIR.png)
Given an iso file, just mount it.

### <a name="_wynt714o4o3i"></a>**for-surveillance-of-sus**

Given .bin cache file. Upon examining with HxD, found out that it was a RDP BMP file (RDP BMP Cache File). So i use bmc-tools to parse it (https://github.com/ANSSI-FR/bmc-tools/)
![image](https://hackmd.io/_uploads/H1v65qBIC.png)

### <a name="_r9ddak6eu3hr"></a>**for-mem-search**

Given a memory dump file. Analyze it using Volatility3. I try so many plugins and have a dead end. But i try to look at the users file using filescan and found out malicious file.
![image](https://hackmd.io/_uploads/SkVA5qr8R.png)
I examine the file and notice it was a poweshell script that do something on the pc
![image](https://hackmd.io/_uploads/B1pC55HIC.png)
![image](https://hackmd.io/_uploads/H1ZJicrUA.png)

### <a name="_keiihphvzm02"></a>**for-tiny-10px**

Given jpg file with 10x10 pixel size, i try to extract the colors from it but found nothing so i try to do something with it size chunk (https://cyberhacktics.com/hiding-information-by-changing-an-images-height/)
![image](https://hackmd.io/_uploads/S1Tks5SUR.png)

`Flag{b1g_en0ugh}` -> i guess it and it was correct

### <a name="_sbwj7l2ppiv9"></a>**For-codebreaker**

Just some regular qr fixing
![image](https://hackmd.io/_uploads/S1tgicrLC.png)
![image](https://hackmd.io/_uploads/ryagoqHL0.png)

### <a name="_o7s77oqjxqme"></a>**for-streamer**

Given pcap file. And notice it contains RTP Packets.
(https://en.wikipedia.org/wiki/Real-time_Transport_Protocol)
![image](https://hackmd.io/_uploads/SkOZoqBIR.png)
RTP Packets is used to do transfer file when streaming. So we need to extract the video (the description said it use H264 encoding).

H264 RTP Payload type is 96, so i set it (https://stackoverflow.com/questions/26164442/decoding-rtp-payload-as-h264-using-wireshark)
![image](https://hackmd.io/_uploads/Hyqmj5BUC.png)

Using h264 extractor plugin, i can extract it (https://github.com/volvet/h264extractor/tree/master).
The video stream is at udp port 59974. The other one is audio stream.
![image](https://hackmd.io/_uploads/SyWEjqB8A.png)
![image](https://hackmd.io/_uploads/rkw4icBIA.png)
