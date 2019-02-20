# @file merkle.py
# @date 29 Dec 2018
# @brief Merkle Tree implementation based on RFC 6962 (Certificate Transparency)

import hashlib, json, time, base64

# The class of a merkle tree of middlebox certificates
class Merkle:
    # Initializer
    # self.certificates: the list of the certificates involved in the tree
    def __init__(self, cert, priv):
        self.certificates = []
        self.cert = cert
        self.priv = priv

    # Add one certificate
    def add_certificate(self, att):
        self.certificates.append(json.dumps(att, sort_keys = True))

    # Get the merkle root value
    def get_merkle_root(self):
        return self.merkle_tree_hash(self.certificates)

    # Get the signed tree head
    def get_sth(self):
        ret = {}
        ret["tree_size"] = len(self.certificates)
        ret["timestamp"] = int(time.time() * 1000)
        ret["sha256_root_hash"] = base64.b64encode(get_merkle_root().encode())
        ths = struct.pack('>BBqqp', 0, 1, ret["timestamp"], ret["tree_size"], ret["sha256_root_hash"])
        ret["tree_head_signature"] = OpenSSL.crypto.sign(self.priv, ths, 'sha256')
        return json.dumps(ret), 200

    # Get the largest power of two less than n
    def largest_power_of_two(self, n):
        k = 1

        while k < n:
            k *= 2

        k /= 2
        return int(k)

    # Make the merkle tree hash value from the list
    def merkle_tree_hash(self, lst):
        return self._merkle_tree_hash(lst)

    def _merkle_tree_hash(self, lst):
        h = hashlib.sha256()

        if len(lst) == 0:
            h.update(b"")
            return h.hexdigest()
        elif len(lst) == 1:
            h.update(b'\x00')
            h.update(lst[0].encode())
            return h.hexdigest()
        else:
            k = self.largest_power_of_two(len(lst))
            h.update(b'\x01')
            h.update(self._merkle_tree_hash(lst[0:k]).encode())
            h.update(self._merkle_tree_hash(lst[k:]).encode())
            return h.hexdigest()

    # Get the list of the audit path of the (m+1)th index in the list
    def merkle_audit_path(self, m, lst):
        n = len(lst)
        k = self.largest_power_of_two(n)

        if n <= 0:
            return []
        elif m == 0 and n == 1:
            return []
        elif n > 1:
            if m < k:
                return self._merkle_audit_path(m, lst[0:k]).append(self._merkle_tree_hash(lst[k:n]))
            else:
                return self._merkle_audit_path(m - k, lst[k:n]).append(self._merkle_tree_hash(lst[0:k]))

    # Get the list of the consistency proof of the tree compared with the previous list
    def merkle_consistency_proof(self, m, lst):
        return _merkle_consistency_subproof(m, lst, True)

    def _merkle_consistency_subproof(self, m, lst, b):
        n = len(lst)
        k = self.largest_power_of_two(n)

        if m > n: # error case
            return []
        elif m == n and b is True:
            return []
        elif m == n and b is False:
            return [merkle_tree_hash(lst)]
        elif m < n:
            if m <= k:
                return _merkle_consistency_subproof(m, lst[0:k], b).append(self._merkle_tree_hash(lst[k:n]))
            else:
                return _merkle_consistency_subproof(m - k, lst[k:n], false).append(self._merkle_tree_hash(lst[0:k]))
