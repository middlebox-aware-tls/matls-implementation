# The implementation is based on RFC 6962 Certificate Transparency.
# Most of sentences in the comments are from the RFC 6962 document.

import os, sys, logging
import OpenSSL.crypto
from pathlib import Path
from merkle.merkle import Merkle
from process import Process
from flask import Flask, json, jsonify, abort, make_response
from flask_restful import Api, Resource, reqparse
from flask_httpauth import HTTPBasicAuth

global context

app = Flask(__name__)
api = Api(app)
auth = HTTPBasicAuth()

def usage():
    print ("This web server is a middlebox transparency log server")
    print ("python3 blockchain_server.py <configuration file> [<logging level(DEBUG/INFO/WARNING/ERROR/CRITICAL)>] <certificate file> <private key file>")
    exit(1)

# URI: /ct/v1/add-chain
# HTTP behavior: POST
# POST: Inputs an array of base64-encoded certificates. Outputs sct_version, id, timestamp, extension, and signature
class CertChain(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument("chain", required=True, type=list, location='json', help="An array of base64-encoded certificates")
        super(CertChain, self).__init__()

    def post(self):
        args = self.reqparse.parse_args()
        return make_response(process.post_certchain(args["chain"]))

# URI: /ct/v1/add-pre-chain
# HTTP behavior: POST
# POST: Inputs an array of base64-encoded Precertificates. Outputs sct_version, id, timestamp, extension, and signature
class PreCertChain(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument("description", required = True, type = str, location = 'json', help="To make a chain, you should describe an explanation about the chain")
        super(PreCertChain, self).__init__()

    def post(self, chain_id):
        args = self.reqparse.parse_args()
        return make_response(process.make_blockchain(chain_id, args["description"]))

# URI: /ct/v1/get-sth
# HTTP behavior: GET
# GET: Retrieve the latest signed tree head. Outputs tree_size, timestamp, sha256_root_hash, and tree_head_signature
class SignedTreeHead(Resource):
    def get(self):
        return make_response(process.make_blockchain(chain_id, args["description"]))

# URI: /ct/v1/get-sth-consistency
# HTTP behavior: GET
# GET: Retrieve the merkle audit proof from the log by the leaf hash. Inputs the tree_size of the first tree and the tree_size of the second tree. Outputs an array of Merkle tree nodes, base64 encoded
class MerkleConsistencyProof(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument("description", required = True, type = str, location = 'json', help="To make a chain, you should describe an explanation about the chain")
        super(Chain, self).__init__()

    def get(self, chain_id):
        return make_response(merkle.get_sth())

# URI: /ct/v1/get-proof-by-hash
# HTTP behavior: GET
# GET: Retrieve the merkle audit proof from the log by the leaf hash. Inputs a base64-encoded v1 leaf hash with the tree_size of the tree on which to base the proof.
class MerkleAuditProof(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument("description", required = True, type = str, location = 'json', help="To make a chain, you should describe an explanation about the chain")
        super(Chain, self).__init__()

    def get(self, chain_id):
        args = self.reqparse.parse_args()
        return make_response(process.make_blockchain(chain_id, args["description"]))

# URI: /ct/v1/get-entries
# HTTP behavior: GET
# GET: Retrieve the entries from the log. Inputs the start index of the first entry to retrieve and the end index of the last entry to retrieve, in decimal
class LogEntries(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument("description", required = True, type = str, location = 'json', help="To make a chain, you should describe an explanation about the chain")
        super(Chain, self).__init__()

    def get(self, chain_id):
        args = self.reqparse.parse_args()
        return make_response(process.make_blockchain(chain_id, args["description"]))

# URI: /ct/v1/get-roots
# HTTP behavior: GET
# GET: Retrieve the accepted root certificates. Outputs the base64-encoded root certificates that are acceptable to the log
class RootCertificates(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument("description", required = True, type = str, location = 'json', help="To make a chain, you should describe an explanation about the chain")
        super(Chain, self).__init__()

    def get(self, chain_id):
        args = self.reqparse.parse_args()
        return make_response(process.make_blockchain(chain_id, args["description"]))

# URI: /ct/v1/get-entry-and-proof
# HTTP behavior: GET
# GET: Retrieve the entry with the merkle audit proof from the log. Inputs the index of the desired entry with the tree_size of the tree. Outputs the base64-encoded MerkleTreeLeaf structure, extra_data, and audit_path.
class LogEntry(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument("description", required = True, type = str, location = 'json', help="To make a chain, you should describe an explanation about the chain")
        super(Chain, self).__init__()

    def get(self, chain_id):
        args = self.reqparse.parse_args()
        return make_response(process.make_blockchain(chain_id, args["description"]))


# The assignment of the mapping between the URI and the related class
api.add_resource(CertChain, '/ct/v1/add-chain')
api.add_resource(PreCertChain, '/ct/v1/add-pre-chain')
api.add_resource(SignedTreeHead, '/ct/v1/get-sth')
api.add_resource(MerkleConsistencyProof, '/ct/v1/get-sth-consistency')
api.add_resource(MerkleAuditProof, '/ct/v1/get-proof-by-hash')
api.add_resource(LogEntries, '/ct/v1/get-entries')
api.add_resource(RootCertificates, '/ct/v1/get-roots')
api.add_resource(LogEntry, '/ct/v1/get-entry-and-proof')

# The process when the application is starting
if __name__ == "__main__":
    # The application will be proceeded without logging
    cert_name = "cert.crt"
    priv_name = "priv.key"

    if len(sys.argv) == 1:
        logging.basicConfig(level=None)

    # Setting the logging level
    elif len(sys.argv) == 2:
        if not sys.argv[1].startswith("--log="):
            logging.error("Invalid arguments")
            usage()
        else:
            arg = sys.argv[1]
            eq = arg.index("=")
            level = arg[eq+1:]
            if level == "DEBUG":
                logging.basicConfig(level=logging.DEBUG)
                logging.debug("The logging level is set to DEBUG")
            elif level == "INFO":
                logging.basicConfig(level=logging.INFO)
                logging.info("The logging level is set to INFO")
            elif level == "WARNING":
                logging.basicConfig(level=logging.WARNING)
                logging.warning("The logging level is set to WARNING")
            elif level == "ERROR":
                logging.basicConfig(level=logging.ERROR)
                logging.error("The logging level is set to ERROR")
            elif level == "CRITICAL":
                logging.basicConfig(level=logging.CRITICAL)
                logging.critical("The logging level is set to CRITICAL")
            else:
                logging.error("Invalid arguments")
                usage()

    elif len(sys.argv) == 4:
        cert_name = sys.argv[2]
        priv_name = sys.argv[3]

    else:
        usage()

    # Load the MT certificate
    st_cert = open(cert_name, "rt").read()
    c = OpenSSL.crypto
    cert = c.load_certificate(c.FILETYPE_PEM, st_cert)
    pk = c.dump_publickey(c.FILETYPE_PEM, cert.get_pubkey())

    # Load the MT privatekey
    st_priv = open(priv_name, "rt").read()
    priv = sk = c.load_privatekey(c.FILETYPE_PEM, st_priv)
 
    # Initialize the context object that processes requests
    merkle = Merkle(cert, priv)
    process = Process(pk, sk)

    app.run(host="0.0.0.0", port=7775, debug=True)
