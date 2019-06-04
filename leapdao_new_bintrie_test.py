from leapdao import EphemDB, new_tree, get, update, make_merkle_proof, verify_proof, compress_proof, decompress_proof
import random
from eth_utils import keccak

KEYS = 500

db = EphemDB()
t = new_tree(db)
for i in range(KEYS):
    t = update(db, t, keccak(i)[12:], keccak(i**3)[12:])
print('%d elements added' % KEYS)
for i in range(KEYS):
    assert get(db, t, keccak(i)[12:]) == keccak(i**3)[12:]
print('Get requests for present elements successful')
for i in range(KEYS + 1, KEYS * 2):
    assert get(db, t, keccak(i)[12:]) == b'\x00' * 20
print('Get requests for absent elements successful')

TL = 0
for i in range(KEYS * 2):
    key = keccak(i)[12:]
    value = keccak(i ** 3)[12:] if i < KEYS else b'\x00' * 20
    proof = make_merkle_proof(db, t, key)
    assert verify_proof(proof, t, key, value)
    assert decompress_proof(compress_proof(proof)) == proof
    TL += len(compress_proof(proof))
print('Average total length at %d keys: %d, %d including key' % (KEYS, TL // KEYS // 2, TL // KEYS // 2 + 32))
