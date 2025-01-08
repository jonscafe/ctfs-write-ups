## X11 Protocol Challenge on NETCOMP 3.0 Qualification

![image](https://hackmd.io/_uploads/SkmZq8YIyl.png)

noticed the packet is transmitted using X11 Protocol

https://www.x.org/releases/X11R7.7/doc/xproto/x11protocol.html

we can use X11 dissector in wireshark

![image](https://hackmd.io/_uploads/B1kw5LtIJx.png)

in this protocol there is an extension named PutImage used to visualize an image file

![image](https://hackmd.io/_uploads/rJTNqEqLyl.png)

https://tronche.com/gui/x/xlib/utilities/manipulating-images.html

https://xmonad.github.io/xmonad-docs/X11-1.10.3.10/Graphics-X11-Xlib-Image.html

it displayed the image, opcode used for the extension is 72. we can use it as filter

![image](https://hackmd.io/_uploads/H1WT9UtUkg.png)

the image is rendered as ZPixMap, we can create a script to render the image using PIL

```
from PIL import Image

hex_data = """
example 
"""

raw_data = bytes.fromhex(hex_data)
raw_data = raw_data[24:] #first 24 bytes is an identity of the packets, we dont need it to render the image
width, height = 250, 250  

expected_size = width * height * 4  # 4 bytes per pixel (RGBA)

if len(raw_data) != expected_size:
    print(f"Warning: Data size mismatch. Expected {expected_size} bytes, got {len(raw_data)} bytes.")
else:
    image = Image.frombytes("RGBA", (width, height), raw_data)

    image.save("output_image.png")
    image.show()
```

originally it transmitted so many images so i need manually try it until i noticed that there are some "nice" image with size 250x250 that we might be the flag

![image](https://hackmd.io/_uploads/H1n7sLFUyl.png)

so we will gonna use it as filter again

![image](https://hackmd.io/_uploads/rkbvo8t8kl.png)

because the raw data is too big, i cant dump it using tshark, i dont know why so i manually dumped it.

![image](https://hackmd.io/_uploads/Hy-tsLYLyx.png)

convert the dumped data into images

```
from PIL import Image
import os

raw_folder = "raw"
width, height = 250, 250  

expected_size = width * height * 4  # 4 bytes per pixel (RGBA)

output_folder = "result"
os.makedirs(output_folder, exist_ok=True)  # Create folder if it doesn't exist

image_count = 0

# Loop through all files in the "raw" folder
for hex_file in os.listdir(raw_folder):
    hex_file_path = os.path.join(raw_folder, hex_file)

    if not os.path.isfile(hex_file_path):
        continue  # Skip if it's not a file

    with open(hex_file_path, "r") as file:
        hex_data = file.read().strip().replace("\n", "")  # Remove newlines and whitespace

    raw_data = bytes.fromhex(hex_data)
    raw_data = raw_data[24:]

    if len(raw_data) != expected_size:
        print(f"Warning: Data size mismatch in {hex_file}. Expected {expected_size} bytes, got {len(raw_data)} bytes.")
        continue

    try:
        image = Image.frombytes("RGBA", (width, height), raw_data)

        output_path = os.path.join(output_folder, f"image_{image_count}.png")
        image.save(output_path)
        print(f"Saved: {output_path}")

        image_count += 1
    except Exception as e:
        print(f"Error processing {hex_file}: {e}")

print(f"Total images saved: {image_count}")
```

![image](https://hackmd.io/_uploads/S1OosItU1l.png)

But the results are still in a random order, so we need to sort them

![image](https://hackmd.io/_uploads/rkZxBE5IJg.png)

when analyzing the raw data noticed the pcap contains so many png that didnt detected with the x11 dissector.

so i got an assumption that the file names is the order (also after consulting to the author hahaha) so i will create a script to reorder it based on what i've found.

```
import os
import shutil
import re

new_order = [
    27, 34, 6, 13, 28, 19, 12, 9, 40, 8, 37, 39, 4, 15, 23, 3, 33, 25, 10, 16,
    7, 32, 31, 1, 38, 20, 26, 5, 24, 29, 14, 30, 17, 0, 11, 18, 2, 21, 22, 35, 36
]

sourceFolder = "result"
desFolder = "flag"

os.makedirs(desFolder, exist_ok=True)

def extract_number(filename):
    match = re.search(r'\d+', filename)  
    return int(match.group()) if match else float('inf') 

files = sorted(os.listdir(sourceFolder), key=extract_number)

if len(files) != len(new_order):
    print(f"Error: Number of files in '{sourceFolder}' ({len(files)}) does not match the expected order ({len(new_order)}).")
    exit(1)

for i, new_name in enumerate(new_order):
    old_file_path = os.path.join(sourceFolder, files[i])
    new_file_name = f"{new_name}" + os.path.splitext(files[i])[1]  
    new_file_path = os.path.join(desFolder, new_file_name)

    shutil.copy(old_file_path, new_file_path)

print(f"Files have been successfully renamed and saved to '{desFolder}'.")
```

![image](https://hackmd.io/_uploads/H1oePNqIyl.png)

Final flag:
`Netcomp{742cb56806e9fb74441367d7eab9c258}`
