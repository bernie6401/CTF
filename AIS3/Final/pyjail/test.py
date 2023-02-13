from typing import Tuple

def jail(code: str) -> Tuple[bool, str]:
    import dis
    if 'flag' in code:
        code = code.replace("flag", "running1")
    if 'system(' in code:
        code = code.replace("system(", "systemm(")
    if 'read(' in code:
        code = code.replace("read()", "close()")
    if 'readline(' in code:
        code = code.replace("readline()", "close()")
    if 'readlines(' in code:
        code = code.replace("readlines()", "close()")
    if 'truncate(' in code:
        code = code.replace("truncate()", "close()")
    if 'cat ' in code:
        code = code.replace("cat","cp")
    if 'less ' in code:
        code = code.replace("less","cp")
    if 'spawn' in code:
        code = code.replace("spawn", 'www')
    code = 'import os\nopen=os.popen=os.system=os.exec=os.read=os.execv=os.execve=os.execl=0\n' + code
    file = 'flag.txt'
    for inst in dis.get_instructions(code):
        if inst.opcode == 100 or file in str(inst.argval) or file.upper() in str(inst.argval):
            return False ,""
    return True, code


file = 'FLAG.TXT'
command = 'SPAWNL'
command2 = 'CA' + 'T'
command3 = '/BI' + 'n/' + command2
print(file.lower(), command.lower(), command2.lower(), command3.lower())
#print(().__class__.__bases__[0].__subclasses__()[138].__init__.__globals__[command.lower()]('P_WAIT', command3.lower(), command2.lower(), file.lower()))



import base64
print(base64.b64decode('Y2F0').index())