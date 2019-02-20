import OpenSSL.crypto
import http.client
import sys, json, base64

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

def usage():
    print ("Middlebox Transparency Client")
    print ("Usage: python3 mt_client.py <mt log server IP> <mt log server port> <leaf certificate (PEM)> <root certificate (PEM)> <output file for Serialized SCT>")
    exit(1)

def get_cert_in_base64(fname):
    start = "-----BEGIN CERTIFICATE-----\n"
    end = "\n-----END CERTIFICATE-----\n"
    c = OpenSSL.crypto
    cert = c.load_certificate(c.FILETYPE_PEM, open(fname).read())
    return base64.b64encode(c.dump_certificate(c.FILETYPE_ASN1, cert))

def get_signed_certificate_timestamp(server, port, lfname, rfname):
    conn = http.client.HTTPConnection(server, port)
    leaf = get_cert_in_base64(lfname).decode()
    root = get_cert_in_base64(rfname).decode()

    js = '{"chain": ["%s","%s"]}' % (leaf, root)
    headers = {"Content-type":"application/json"}

    conn.request("POST", "/ct/v1/add-chain", js, headers)

    response = conn.getresponse()
    sct = response.read().decode()
    js = json.loads(sct)
    return sct

def output_sct(ofname, sct):
    js = json.loads(sct)
    f = open(ofname, "wb")
    f.write((SCT_VERSION_V1).to_bytes(1, byteorder='big'))
    f.write(js["id"].encode())
    f.write(js["timestamp"].to_bytes(8, byteorder='big'))
    f.write((0).to_bytes(2, byteorder='big'))
    f.write((HASH_ALGORITHM_SHA256).to_bytes(1, byteorder='big'))
    f.write((SIGN_ALGORITHM_ECDSA).to_bytes(1, byteorder='big'))
    f.write((len(js["signature"])).to_bytes(2, byteorder='big'))
    f.write(js["signature"].encode())
    f.close()

def main():
    if len(sys.argv) != 6:
        usage()

    mt_server = sys.argv[1]
    mt_server_port = int(sys.argv[2])
    leaf_fname = sys.argv[3]
    root_fname = sys.argv[4]
    ofname = sys.argv[5]
    
    sct = get_signed_certificate_timestamp(mt_server, mt_server_port, leaf_fname, root_fname)
    output_sct(ofname, sct)

if __name__ == "__main__":
    main()
