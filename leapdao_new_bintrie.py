from eth_utils import keccak, encode_hex

class EphemDB():
    def __init__(self, kv=None):
        self.kv = kv or {}

    def get(self, k):
        return self.kv.get(k, None)

    def put(self, k, v):
        self.kv[k] = v

    def delete(self, k):
        del self.kv[k]

zerohashes = [b'\x00' * 20]
for i in range(160):
    zerohashes.insert(0, keccak(zerohashes[0] + zerohashes[0])[12:])

def new_tree(db):
    h = b'\x00' * 20
    for i in range(160):
        newh = keccak(h + h)[12:]
        db.put(newh, h + h)
        h = newh
    return h

def key_to_path(k):
    o = 0
    for c in k:
        o = (o << 8) + c
    return o

def descend(db, root, *path):
    v = root
    for p in path:
        if p:
            v = db.get(v)[20:]
        else:
            v = db.get(v)[:20]
    return v

def get(db, root, key):
    v = root
    path = key_to_path(key)
    for i in range(160):
        if (path >> 159) & 1:
            v = db.get(v)[20:]
        else:
            v = db.get(v)[:20]
        path <<= 1
    return v

def update(db, root, key, value):
    v = root
    path = path2 = key_to_path(key)
    sidenodes = []
    for i in range(160):
        if (path >> 159) & 1:
            sidenodes.append(db.get(v)[:20])
            v = db.get(v)[20:]
        else:
            sidenodes.append(db.get(v)[20:])
            v = db.get(v)[:20]
        path <<= 1
    v = value
    for i in range(160):
        if (path2 & 1):
            newv = keccak(sidenodes[-1] + v)[12:]
            db.put(newv, sidenodes[-1] + v)
        else:
            newv = keccak(v + sidenodes[-1])[12:]
            db.put(newv, v + sidenodes[-1])
        path2 >>= 1
        v = newv
        sidenodes.pop()
    return v

def make_merkle_proof(db, root, key):
    v = root
    path = key_to_path(key)
    sidenodes = []
    for i in range(160):
        if (path >> 159) & 1:
            sidenodes.append(db.get(v)[:20])
            v = db.get(v)[20:]
        else:
            sidenodes.append(db.get(v)[20:])
            v = db.get(v)[:20]
        path <<= 1
    return sidenodes

def verify_proof(proof, root, key, value):
    path = key_to_path(key)
    v = value
    for i in range(160):
        if (path & 1):
            newv = keccak(proof[-1-i] + v)[12:]
        else:
            newv = keccak(v + proof[-1-i])[12:]
        path >>= 1
        v = newv
    return root == v

def compress_proof(proof):
    bits = bytearray(20)
    oproof = b''
    for i, p in enumerate(proof):
        if p == zerohashes[i+1]:
            bits[i // 8] ^= 1 << i % 8
        else:
            oproof += p
    return bytes(bits) + oproof

def decompress_proof(oproof):
    proof = []
    bits = bytearray(oproof[:20])
    pos = 20
    for i in range(160):
        if bits[i // 8] & (1 << (i % 8)):
            proof.append(zerohashes[i+1])
        else:
            proof.append(oproof[pos: pos + 20])
            pos += 20
    return proof
