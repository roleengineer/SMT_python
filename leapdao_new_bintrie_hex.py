from eth_utils import keccak, encode_hex

class EphemDB():
    def __init__(self, kv=None):
        self.reads = 0
        self.writes = 0
        self.kv = kv or {}

    def get(self, k):
        self.reads += 1
        return self.kv.get(k, None)

    def put(self, k, v):
        self.writes += 1
        self.kv[k] = v

    def delete(self, k):
        del self.kv[k]

# Hashes of empty subtrees
zerohashes = [b'\x00' * 20]
for i in range(160):
    zerohashes.insert(0, keccak(zerohashes[0] + zerohashes[0])[12:])

# Create a new empty tree
def new_tree(db):
    return zerohashes[0]

# Convert a binary key into an integer path value
def key_to_path(k):
    return int.from_bytes(k, 'big')

tt160m1 = 2**160 - 1

# And convert back
def path_to_key(k):
    return (k & tt160m1).to_bytes(20, 'big')

# Read a key from a given tree
def get(db, root, key):
    v = root
    path = key_to_path(key)
    for i in range(0, 160, 4):
        if v == zerohashes[i]:
            return b'\x00' * 20
        child = db.get(v)
        if len(child) == 41:
            if (path % 2**160) == key_to_path(child[1:21]):
                return child[21:]
            else:
                return b'\x00' * 20
        else:
            index = (path >> 156) & 15
            v = child[20*index: 20*index+20]
        path <<= 4
    return v

# Make a root hash of a (sub)tree with a single key/value pair
def make_single_key_hash(path, depth, value):
    if depth == 160:
        return value
    elif (path >> 159) & 1:
        return keccak(zerohashes[depth+1] + make_single_key_hash(path << 1, depth + 1, value))[12:]
    else:
        return keccak(make_single_key_hash(path << 1, depth + 1, value) + zerohashes[depth+1])[12:]

# Hash together 16 elements
def hash_16_els(vals):
    assert len(vals) == 16
    for _ in range(4):
        vals = [keccak(vals[i] + vals[i+1])[12:] for i in range(0, len(vals), 2)]
    return vals[0]

# Make a root hash of a (sub)tree with two key/value pairs, and save intermediate nodes in the DB
def make_double_key_hash(db, path1, path2, depth, value1, value2):
    if depth == 160:
        raise Exception("Cannot fit two values into one slot!")
    if ((path1 >> 156) & 15) == ((path2 >> 156) & 15):
        children = [zerohashes[depth+4]] * 16
        children[(path1 >> 156) & 15] = make_double_key_hash(db, path1 << 4, path2 << 4, depth + 4, value1, value2)
    else:
        Lkey = ((path1 >> 156) & 15)
        L = make_single_key_hash(path1 << 4, depth + 4, value1)
        Rkey = ((path2 >> 156) & 15)
        R = make_single_key_hash(path2 << 4, depth + 4, value2)
        db.put(L, b'\x01' + path_to_key(path1 << 4) + value1)
        db.put(R, b'\x01' + path_to_key(path2 << 4) + value2)
        children = [zerohashes[depth+4]] * 16
        children[Lkey] = L
        children[Rkey] = R
    h = hash_16_els(children)
    db.put(h, b''.join(children))
    return h

# Update a tree with a given key/value pair
def update(db, root, key, value):
    return _update(db, root, key_to_path(key), 0, value)

def _update(db, root, path, depth, value):
    if depth == 160:
        return value
    # Update an empty subtree: make a single-key subtree
    if root == zerohashes[depth]:
        k = make_single_key_hash(path, depth, value)
        db.put(k, b'\x01' + path_to_key(path) + value)
        return k
    child = db.get(root)
    # Update a single-key subtree: make a double-key subtree
    if len(child) == 41:
        origpath, origvalue = key_to_path(child[1:21]), child[21:]
        return make_double_key_hash(db, path, origpath, depth, value, origvalue)
    # Update a multi-key subtree: recurse down
    else:
        assert len(child) == 320
        index = (path >> 156) & 15
        new_value = _update(db, child[index*20: index*20+20], path << 4, depth + 4, value)
        new_children = [new_value if i == index else child[20*i:20*i+20] for i in range(16)]
        h = hash_16_els(new_children)
        db.put(h, b''.join(new_children))
        return h

def multi_update(db, root, keys, values):
    for k, v in zip(keys, values):
        root = update(db, root, k, v)
    return root
