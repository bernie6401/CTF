from pwn import *
from itertools import combinations
from Crypto.Util.number import isPrime, inverse, long_to_bytes

context.arch = 'amd64'

def sub_lists (l):
    comb = []
    for i in range(1,len(l)+1):
        comb += [list(j) for j in combinations(l, i)]
    return comb

def main():
    r = remote("saturn.picoctf.net", 65518)

    c = int(r.recvline().strip().decode().split(" ")[-1])
    d = int(r.recvline().strip().decode().split(" ")[-1])
    e = 65537
    log.info(f"c = {c}\nd = {d}")

    k_phi = d * e - 1
    print("k_phi = ", k_phi)

    k_phi_factor = eval(input("Please go to the online tool page and choose comma separated factors and paste the fatorize result here: "))
    combos = sub_lists(k_phi_factor)

    '''Find (p-1)'''
    primes = set()
    for l in combos:
        product = 1
        # multiply them together to get p-1
        for k in l:
            product = product * k
        if product.bit_length()==128 and isPrime(product+1):
            primes.add(product+1)
    print(primes)

    if len(primes) == 2:
        phi = 1
        n = 1
        for candidate in primes:
            phi *= (candidate - 1)
            n *= candidate


        assert inverse(e, phi) == d
        print(long_to_bytes(pow(c, d, n)))
        r.sendline(long_to_bytes(pow(c, d, n)))
        r.interactive()
        r.close()
        sys.exit(0)

    else:
        r.close()
        return False

if __name__ == '__main__':
    while not main():
        main()