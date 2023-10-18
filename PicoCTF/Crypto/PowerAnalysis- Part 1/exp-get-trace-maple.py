from pwn import remote
from pathlib import Path
import os, ast

traces = Path("traces")
traces.mkdir(exist_ok=True)

for i in range(100):
    io = remote("saturn.picoctf.net", 59935)
    pt = os.urandom(16)
    io.sendline(pt.hex().encode())
    io.recvuntil(b"result:  ")
    trace = ast.literal_eval(io.recvlineS().strip())
    f = traces / f"trace{i:02d}.txt"
    f.write_text(
        f"""Plaintext: {pt.hex()}
Power trace: {trace}
    """
    )
    io.close()