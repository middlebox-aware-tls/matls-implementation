import OpenSSL.crypto
import os, hashlib, time, base64, struct
from flask import json, jsonify

SUCCESS = 1
FAILURE = -1

SCT_VERSION_V1 = 0

ST_CERTIFICATE_TIMESTAMP = 0
ST_TREE_HASH = 1

X509_ENTRY = 0
PRECERT_ENTRY = 1

HASH_ALGORITHM_NONE = 0
HASH_ALGORITHM_MD5 = 1
HASH_ALGORITHM_SHA1 = 2
HASH_ALGORITHM_SHA224 = 3
HASH_ALGORITHM_SHA256 = 4
HASH_ALGORITHM_SHA384 = 5
HASH_ALGORITHM_SHA512 = 6

SIGN_ALGORITHM_ANON = 0
SIGN_ALGORITHM_RSA = 1
SIGN_ALGORITHM_DSA = 2
SIGN_ALGORITHM_ECDSA = 3

# The process module of the middlebox transparency log server
class Process:
    def __init__(self, pk, sk):
        self.publickey = pk
        self.privatekey = sk

    def post_certchain(self, chain):
        leaf_cert = chain[0]
        cert = base64.b64decode(leaf_cert)

        # Version
        version = SCT_VERSION_V1

        # Log ID
        c = OpenSSL.crypto
        leaf_cert = c.load_certificate(c.FILETYPE_ASN1, cert)
        leaf_dump = c.dump_certificate(c.FILETYPE_ASN1, leaf_cert)
        pk = c.dump_publickey(c.FILETYPE_ASN1, leaf_cert.get_pubkey())
        h = hashlib.sha256()
        h.update(pk)
        log_id = h.hexdigest()

        # Timestamp
        timestamp = int(time.time() * 1000)

        # SCT signature
        signature = self.make_signature(version, timestamp, X509_ENTRY, leaf_dump, extensions = None)

        return jsonify({ "sct_version": SCT_VERSION_V1,
                "id": log_id,
                "timestamp": timestamp,
                "signature": signature }), 200

    def make_signature(self, version, timestamp, entry_type, cert, extensions):
        clen = struct.pack(">L", len(cert))[1:]
        # tbs: to be signed
        tbs = (SCT_VERSION_V1).to_bytes(1, byteorder='big')
        tbs += (ST_CERTIFICATE_TIMESTAMP).to_bytes(1, byteorder='big')
        tbs += (timestamp).to_bytes(8, byteorder='big')
        tbs += (X509_ENTRY).to_bytes(2, byteorder='big')
        tbs += (len(cert)).to_bytes(3, byteorder='big')
        tbs += cert

        return base64.b64encode(OpenSSL.crypto.sign(self.privatekey, tbs, 'sha256')).decode('ascii')
