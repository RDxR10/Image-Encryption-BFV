import numpy as np
from numpy.polynomial import polynomial as poly
from PIL import Image
import time
#import itertools


def gen_binary_poly(size):
    return np.random.randint(0, 2, size, dtype=np.int64)


def gen_uniform_poly(size, modulus):
    return np.random.randint(0, modulus, size, dtype=np.int64)


def gen_normal_poly(size):
    return np.int64(np.random.normal(0, 2, size=size))


# Functions for polynomial evaluation in Z_q[X]/(X^N + 1)

def polymul(x, y, modulus, poly_mod):

    return np.int64(
        np.round(poly.polydiv(poly.polymul(x, y) %
                              modulus, poly_mod)[1] % modulus)
    )


def polyadd(x, y, modulus, poly_mod):
    return np.int64(
        np.round(poly.polydiv(poly.polyadd(x, y) %
                              modulus, poly_mod)[1] % modulus)
    )


# Functions for keygen, encryption and decryption

def keygen(size, modulus, poly_mod):
    s = gen_binary_poly(size)
    a = gen_uniform_poly(size, modulus)
    e = gen_normal_poly(size)
    b = polyadd(polymul(-a, s, modulus, poly_mod), -e, modulus, poly_mod)

    return (b, a), s


def encrypt(pk, size, q, t, poly_mod, pt):
    m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    delta = q // t
    scaled_m = delta * m
    e1 = gen_normal_poly(size)
    e2 = gen_normal_poly(size)
    u = gen_binary_poly(size)
    ct0 = polyadd(
        polyadd(
            polymul(pk[0], u, q, poly_mod),
            e1, q, poly_mod),
        scaled_m, q, poly_mod
    )
    ct1 = polyadd(
        polymul(pk[1], u, q, poly_mod),
        e2, q, poly_mod
    )
    return (ct0, ct1)


def decrypt(sk, size, q, t, poly_mod, ct):
    scaled_pt = polyadd(
        polymul(ct[1], sk, q, poly_mod),
        ct[0], q, poly_mod
    )
    delta = q // t
    decrypted_poly = np.round(scaled_pt / delta) % t
    return int(decrypted_poly[0])


# Function for adding and multiplying encrypted values

def add_plain(ct, pt, q, t, poly_mod):
    size = len(poly_mod) - 1
    m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    delta = q // t
    scaled_m = delta * m
    new_ct0 = polyadd(ct[0], scaled_m, q, poly_mod)
    return (new_ct0, ct[1])


def add_cipher(ct1, ct2, q, poly_mod):
    new_ct0 = polyadd(ct1[0], ct2[0], q, poly_mod)
    new_ct1 = polyadd(ct1[1], ct2[1], q, poly_mod)
    return (new_ct0, new_ct1)


def mul_plain(ct, pt, q, t, poly_mod):
    size = len(poly_mod) - 1
    m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    new_c0 = polymul(ct[0], m, q, poly_mod)
    new_c1 = polymul(ct[1], m, q, poly_mod)
    return (new_c0, new_c1)


def factorize(n):
    factors = []
    for i in range(1, int(n**0.5) + 1):
        if n % i == 0:
            factors.append((i, n // i))
    return factors[-1]


def read_image(file_path):
    with Image.open(file_path) as img:
        return np.array(img.convert("L"), dtype=np.int64).flatten()

# Function to convert a 1D array back into an image
def array_to_image(arr, shape):
    #arr = np.reshape(arr, (shape[0], shape[1], 3))
    #return Image.fromarray(np.uint8(arr))
    return Image.fromarray(np.uint8(np.reshape(arr, shape)))  #8 bit depth
    


def encrypt_image(pk, size, q, t, poly_mod, file_path):
    image_arr = read_image(file_path)
    ct = []
    for pt in image_arr:
        ct.append(encrypt(pk, size, q, t, poly_mod, pt))
    
    #new_ct = list(itertools.chain(*ct))
    return ct


def decrypt_(sk, size, q, t, poly_mod, ct, shape):
    decrypted_arr = []
    for c in ct:
        decrypted_arr.append(decrypt(sk, size, q, t, poly_mod, c))
    return array_to_image(decrypted_arr, shape)



if __name__ == "__main__":
    n = 2**4 #polynomial modulus degree
    q = 2**15 #ciphertext modulus
    t = 2**8 #plaintext modulus
    poly_mod = np.array([1] + [0] * (n - 1) + [1])
    start_time = time.time()

    pk, sk = keygen(n, q, poly_mod)    
    file_path = "2F81j.jpg"
    encrypted_ct = encrypt_image(pk, n, q, t, poly_mod, file_path)
    dec = decrypt_(sk, n, q, t, poly_mod, encrypted_ct, factorize(len(encrypted_ct))) 
    dec.save("dec.jpg")
    end_time = time.time()
    print("Time taken:", end_time - start_time, "seconds")
    
    
    """
    f = np.ravel(encrypted_ct).flatten()
    flat_list = []
    for arr in f:
        flat_list.extend(arr)
    encr_image = array_to_image(flat_list, factorize(len(flat_list)))
    encr_image.show()
    """