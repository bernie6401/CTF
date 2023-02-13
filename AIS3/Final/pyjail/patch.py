from typing import Tuple

def jail(code: str) -> Tuple[bool, str]:
    # code = code.lower()
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
        if inst.opcode == 100 or file in str(inst.argval):
            return False ,""
    return True, code