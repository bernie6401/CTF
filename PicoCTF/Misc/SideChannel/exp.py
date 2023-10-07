from time import *
from subprocess import *
from tqdm import trange

time_lapse = []
guess_pin = list("99999999")
for i in trange(8):
    for j in range(10):
        guess_pin[i] = str(j)
        payload = "".join(guess_pin)
        start = time_ns()
        # run(['echo {payload} | ./pin_checker'])
        # Popen(['echo', payload, '|', './pin_checker'], shell=True)
        p = Popen("./pin_checker", stdin=PIPE, stdout=PIPE, universal_newlines=True, shell=True)
        p.communicate(input=payload)
        time_lapse.append(time_ns() - start)
    guess_pin[i] = str(time_lapse.index(max(time_lapse)))
    time_lapse = []

print("".join(guess_pin))