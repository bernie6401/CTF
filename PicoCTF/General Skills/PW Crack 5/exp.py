import subprocess
from subprocess import Popen as p

f = open("dictionary.txt", "r")

for i in range(65536):
    guess = f.readline()
    echo_str = p(["echo", guess], stdout=subprocess.PIPE, text=True)
    return_str = p(["python", "level5.py"], stdin=echo_str.stdout, stdout=subprocess.PIPE, text=True)
    output, error = return_str.communicate()
    if "That password is incorrect" not in output:
        print(guess)