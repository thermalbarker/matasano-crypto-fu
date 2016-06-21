

# A = (g ** a) % p
# Nice explanation here:
# https://en.wikipedia.org/wiki/Modular_exponentiation
def tom_modexp(g, a, p):
    if (p == 1):
        return 0
    c = 1
    e = 0
    while e < a: 
        c = (c * g) % p
        e += 1
    return c



