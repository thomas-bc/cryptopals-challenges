import codecs
from binascii import unhexlify
import inspect
from base64 import b64decode



def xor(str1: str, str2: str):
    '''Returns hex repr of XOR'ed str1 and str2'''
    str1b = codecs.decode(str1, 'hex')
    str2b = codecs.decode(str2, 'hex')

    L = []
    for (el1, el2) in zip(str1b, str2b):
        L.append(el1^el2)

    return bytes(L).hex()

def bxor(str1: bytes, str2: bytes):
    L = []
    for (el1, el2) in zip(str1, str2):
        L.append(el1^el2)

    return bytes(L)


ascii_text_chars = list(range(97, 122)) + [32]
def letter_ratio(input_bytes):
    nb_letters = sum([ x in ascii_text_chars for x in input_bytes])
    return nb_letters / len(input_bytes)

def is_probably_text(input_bytes):
    r = letter_ratio(input_bytes)
    return True if r>0.7 else False


def decode(enc):
    for i in range(2**8): # for every possible key
        # converting the key from a number to a byte
        candidate_key = i.to_bytes(1, byteorder='big')
    #for letter in alph:
        decoded_candidate = bxor(codecs.decode(enc, 'hex'), candidate_key*len(enc))
        if is_probably_text(decoded_candidate):
            return decoded_candidate



def find_file(file_name: str):
    f = open(file_name, 'r')
    for line in f.readlines():
        res = decode(line.strip())
        if res!=None:
            print(res)


def keyphrase_encode(string: bytes, keyphrase: bytes):
    key = keyphrase*(len(string)//3) + keyphrase[0:len(string)%3]
    return bxor(string, key).hex()

def b_edit_dist(str1: bytes, str2: bytes):
    return sum(bin(byte).count('1') for byte in bxor(str1,str2))


def score_vigenere_key_size(candidate_key_size, ciphertext):
    # as suggested in the instructions,
    # we take samples bigger than just one time the candidate key size
    slice_size = 2*candidate_key_size

    # the number of samples we can make
    # given the ciphertext length
    nb_measurements = len(ciphertext) // slice_size - 1

    # the "score" will represent how likely it is
    # that the current candidate key size is the good one
    # (the lower the score the *more* likely)
    score = 0
    for i in range(nb_measurements):

        s = slice_size
        k = candidate_key_size
        # in python, "slices" objects are what you put in square brackets
        # to access elements in lists and other iterable objects.
        # see https://docs.python.org/3/library/functions.html#slice
        # here we build the slices separately
        # just to have a cleaner, easier to read code
        slice_1 = slice(i*s, i*s + k)
        slice_2 = slice(i*s + k, i*s + 2*k)

        score += b_edit_dist(ciphertext[slice_1], ciphertext[slice_2])

    # normalization: do not forget this
    # or there will be a strong biais towards long key sizes
    # and your code will not detect key size properly
    score /= candidate_key_size
    
    # some more normalization,
    # to make sure each candidate is evaluated in the same way
    score /= nb_measurements

    return score

def find_key_size(ciphertext, min_=2, max_=40):
    key = lambda x: score_vigenere_key_size(x, ciphertext)
    return min(range(min_, max_), key=key)

def break_vigenere(file_name: str):
    
    with open('ecrypted.txt') as file:
        cyphertext = b64decode(file.read())
        key_size = find_key_size(cyphertext)

        BLOCKS = []
        for size in range(key_size):
            BLOCKS.append(cyphertext[size::key_size])
    
    return BLOCKS

def main():
    hex_rep = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    hex_d = codecs.decode(hex_rep, 'hex')
    #print(codecs.encode(hex_d, 'base64'))
    #print(codecs.encode(hex_d, 'hex'))
    #print()

    #a = xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')
    #print(a)

    #print(decode('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))
    #print(decode('7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f'))

    #find_file('data.txt')

    #print(keyphrase_encode(b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", b'ICE'))
    print(b_edit_dist(b'this is a test', b'wokka wokka!!!'))
    for block in break_vigenere('ecrypted.txt'):
        print(block)
    


if __name__ == '__main__':
    main()