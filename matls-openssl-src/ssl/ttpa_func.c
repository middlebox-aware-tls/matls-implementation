#include "ttpa.h"

// Make cc content body
// Input
//   out: BIO for the standard output
//   content: cc content
//   alice_pub: origin's public key
//   carol_pub: edge's public key
//   nid: signature type
//   len: length of the cc content
// Output Success: 1, Failure: 0
int make_cc_content_body(unsigned char **content, EVP_PKEY *alice_pub, EVP_PKEY *carol_pub, int nid, int *len)
{
	// Declare the variables related to the relation
	BIO *pub_relation = NULL;
	unsigned char *pub_relation_sha;
	int shalen, i;

	// Declare the variables related to the timestamp
	struct timeval curr;
	gettimeofday(&curr, NULL);
	unsigned long ts = curr.tv_sec;
	unsigned int duration = 31536000;

	printf("PROGRESS: Make H(orig||edge)\n");
	pub_relation = BIO_new(BIO_f_md());

	// Set the message digests according to the nid
	switch (nid)
	{
		case NID_sha1:
			BIO_set_md(pub_relation, EVP_sha1());
			shalen = SHA_DIGEST_LENGTH;
			printf("PROGRESS: Hash algorithm is set to SHA1\n");
			break;
		case NID_sha224:
			BIO_set_md(pub_relation, EVP_sha224());
			shalen = SHA224_DIGEST_LENGTH;
			printf("PROGRESS: Hash algorithm is set to SHA224\n");
			break;
		case NID_sha256:
			BIO_set_md(pub_relation, EVP_sha256());
			shalen = SHA256_DIGEST_LENGTH;
			printf("PROGRESS: Hash algorithm is set to SHA256\n");
			break;
		default:
			printf("PROGRESS: Unknown Hash algorithm\n");
			return 0;
	}

	pub_relation_sha = (unsigned char *)OPENSSL_malloc(shalen);

	// Make the hash, H(alice||carol)
	PEM_write_bio_PUBKEY(pub_relation, alice_pub);
	PEM_write_bio_PUBKEY(pub_relation, carol_pub);
	BIO_gets(pub_relation, (char *)pub_relation_sha, shalen);

	// Print the info
	printf("PROGRESS: Print Relation\n");

	for (i=0; i<shalen; i++)
	{
		if (i % 10 == 0)
			printf("\n");
		printf("%02x\t", pub_relation_sha[i]);
	}
	printf("\n");

	printf("PROGRESS: sizeof(unsigned long):\t %lu\n", sizeof(unsigned long));
	printf("PROGRESS: sizeof(unsigned int):\t %lu\n", sizeof(unsigned int));
	printf("PROGRESS: current time:\t %lu\n", ts);
	printf("PROGRESS: duration:\t %u\n", duration);
	printf("PROGRESS: hash algorithm type:\t %u\n", nid);

	// Make the final message
	uint16_t ht = (uint16_t) nid;
	*len = sizeof(ts) + sizeof(duration) + sizeof(ht) + shalen;
	printf("PROGRESS: length of cc_content_body: %d\n", *len);
	*content = (unsigned char *)OPENSSL_malloc(*len);
	unsigned char *p;
	p = *content;
	t2n8(ts, p);
	d2n4(duration, p);
	s2n(ht, p);
	memcpy(p, pub_relation_sha, shalen);

	printf("PROGRESS: print cc_content_body\n");
	for (i=0; i<*len; i++)
	{
		if (i % 10 == 0)
			printf("\n");
		printf("%02x\t", (*content)[i]);
	}
	printf("\n");

	return 1;
}

// Make the cc request message
// Input
//   out: BIO for the standard output
//   request: the final message
//   msg: cc content
//   msg_len: length of cc content
//   carol_priv: edge's private key
//   nid: signature algorithm
//   len: the length of the final message
// Output
//   Success: 1, Failure: 0
int make_cc_request(unsigned char **request, unsigned char *msg, int msg_len, EVP_PKEY *carol_priv, int nid, int *len)
{
	unsigned char *sigblk, *p;
	size_t sigblk_len;

	if (!make_signature_block(&sigblk, msg, msg_len, carol_priv, nid, &sigblk_len))
	{
		printf("ERROR: make the signature block failed\n");
		goto err;
	}
	printf("PROGRESS: make the signature block for the cc content success\n");

	*len = sizeof(uint16_t) + msg_len + sigblk_len;

	printf("Length of cc request: %d\n", *len);

	// Make the final message - cc request
	*request = (unsigned char *)OPENSSL_malloc(*len);
	p = *request;
	s2n(msg_len, p);
	memcpy(p, msg, msg_len);
	p += msg_len;
	memcpy(p, sigblk, sigblk_len);

	OPENSSL_free(sigblk);

	return 1;

err:
	return 0;
}

int make_cc_request_with_verify_cc(unsigned char **request, unsigned char *msg, int msg_len, EVP_PKEY *carol_priv, EVP_PKEY *alice_pub, EVP_PKEY *carol_pub, int nid, int *len)
{
	if (!verify_cc_content_body(msg, alice_pub, carol_pub))
	{
		printf("ERROR: Verify cc content body failure in make_cc_request_with_verify_cc\n");
		return 0;
	}
	return make_cc_request(request, msg, msg_len, carol_priv, nid, len);
}

// Make the cc_response message (len || cc_request || Signature type || Signature length || Signature)
// Input
//   out: BIO for the standard output
//   response: the cc_response message
//   request: the cc_request message
//   req_len: the length of the request
//   alice_priv: the alice's private key
//   alice_pub: the alice's public key
//   carol_pub: the carol's public key
//   nid: the signature algorithm
//   len: the length of the cc_response
// Output
//   Success 1
//   Failure 0
int make_cc_response(unsigned char **response, unsigned char *request, int req_len, EVP_PKEY *alice_priv, int nid, int *len)
{
	unsigned char *sigblk, *p;
	size_t sigblk_len;

	printf("PROGRESS: Make the cc response\n");

	if (!make_signature_block(&sigblk, request, req_len, alice_priv, nid, &sigblk_len))
	{
		printf("ERROR: make the signature block failed\n");
		goto err;
	}
	printf("PROGRESS: make the signature block for the cc content success\n");

	*len = sizeof(uint16_t) + req_len + sigblk_len;

	printf("Length of cc response: %d\n", *len);

	// Make the final message - cc response
	*response = (unsigned char *)OPENSSL_malloc(*len);
	p = *response;
	s2n(req_len, p);
	memcpy(p, request, req_len);
	p += req_len;
	memcpy(p, sigblk, sigblk_len);

	OPENSSL_free(sigblk);

	return 1;

err:
	return 0;
}

int make_cc_response_with_verify_request(unsigned char **response, unsigned char *request, int req_len, EVP_PKEY *alice_priv, EVP_PKEY *alice_pub, EVP_PKEY *carol_pub, int nid, int *len)
{
	if (!verify_cc_request(request, alice_pub, carol_pub))
	{
		printf("ERROR: Verify the cc request failed in make_cc_response_with_verify_request\n");
		return 0;
	}
	printf("PROGRESS: Verify the cc request success in make_cc_response_with_verify_request\n");

	return make_cc_response(response, request, req_len, alice_priv, nid, len);
}

// Make the signature block composed of (Signature Type || Signature Length || Signature)

int make_signature_block(unsigned char **sigblk, unsigned char *msg, int msg_len, EVP_PKEY *priv, int nid, size_t *sigblk_len)
{
	int i, rc, rc1, rc2;
	EVP_MD_CTX *ctx;
	unsigned char *sig, *p;
	size_t sig_len;
	uint16_t sig_type;

	ctx = EVP_MD_CTX_create();
	if (ctx == NULL)
	{
		printf("EVP_MD_CTX_create failed\n");
		goto err;
	}

	// Initialize the md according to nid
	switch (nid)
	{
		case NID_sha1:
			rc1 = EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
			rc2 = EVP_DigestSignInit(ctx, NULL, EVP_sha1(), NULL, priv);
			sig_type = NID_sha1;
			break;
		case NID_sha224:
			rc1 = EVP_DigestInit_ex(ctx, EVP_sha224(), NULL);
			rc2 = EVP_DigestSignInit(ctx, NULL, EVP_sha224(), NULL, priv);
			sig_type = NID_sha224;
			break;
		case NID_sha256:
			rc1 = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
			rc2 = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv);
			sig_type = NID_sha256;
			break;
		default:
			printf("Unknown Hash algorithm\n");
			goto err;
	}

	// Make the signature
	if (rc1 != 1)
	{
		printf("PROGRESS: Digest Init Failed\n");
		goto err;
	}

	if (rc2 != 1)
	{
		printf("PROGRESS: DigestSign Init Failed\n");
		goto err;
	}

	rc = EVP_DigestSignUpdate(ctx, msg, msg_len);
	if (rc != 1)
	{
		printf("PROGRESS: DigestSign Update Failed\n");
		goto err;
	}

	rc = EVP_DigestSignFinal(ctx, NULL, &sig_len);
	if (rc != 1)
	{
		printf("PROGRESS: DigestSign Final Failed\n");
		goto err;
	}

	if (sig_len <= 0)
	{
		printf("PROGRESS: DigestSign Final Failed\n");
		goto err;
	}

	printf("PROGRESS: Signature length: %d\n", (int)sig_len);
	sig = OPENSSL_malloc(sig_len);

	if (sig == NULL)
	{
		printf("PROGRESS: OPENSSL_malloc error\n");
		goto err;
	}

	rc = EVP_DigestSignFinal(ctx, sig, &sig_len);
	if (rc != 1)
	{
		printf("PROGRESS: DigestSign Final Failed\n");
		goto err;
	}

	*sigblk_len = 2 * sizeof(uint16_t) + sig_len;
	*sigblk = (unsigned char *)OPENSSL_malloc(*sigblk_len);
	p = *sigblk;
	s2n(sig_type, p);
	s2n(sig_len, p);
	memcpy(p, sig, sig_len);

	printf("PROGRESS: Sig in make cc >>>\n");
	for (i=0; i<sig_len; i++)
	{
		if (i % 10 == 0)
			printf("\n");
		printf("%02X ", sig[i]);
	}
	printf("\n");

	printf("PROGRESS: Length of message: %d\n", msg_len);
	printf("PROGRESS: Signature type: %d\n", (int)sig_type);
	printf("PROGRESS: Length of signature: %d\n", (int)sig_len);

	OPENSSL_free(sig);
	EVP_MD_CTX_cleanup(ctx);

	return 1;

err:
	EVP_MD_CTX_cleanup(ctx);

	return 0;
}

// Verify the cc content 
// Input
//   out: BIO for the standard output
//   content: cc content
//   alice_pub: origin's public key
//   carol_pub: edge's public key
// Output
//   Success: 1, Failure: 0
int verify_cc_content_body(unsigned char *content, EVP_PKEY *alice_pub, EVP_PKEY *carol_pub)
{
	unsigned char *p = content;
	unsigned char *hash;
	unsigned char *pub_relation_sha;
	uint64_t ts;
	uint32_t duration;
	uint16_t ht;
	int len, cmp;
	struct timeval tv;
	unsigned long curr;

	BIO *pub_relation = NULL;
	
	n2t8(p, ts);
	n2d4(p, duration);

	printf("PROGRESS: verify timestamp: %lu\n", ts);
	printf("PROGRESS: verify duration: %u\n", duration);

	// Get the current time
	gettimeofday(&tv, NULL);
	curr = tv.tv_sec;

	// Verify whether in the valid time
	if ((curr >= ts) && (curr < ts + duration))
	{
		printf("PROGRESS: current time is in the valid duration: %lu\n", curr);
	}
	else
	{
		printf("PROGRESS: verify error. current time is not in the valid duration\n");
		goto err;
	}

	n2s(p, ht);
	pub_relation = BIO_new(BIO_f_md());

	// Set the hash algorithm according to nid
	switch (ht)
	{
		case NID_sha1:
			BIO_set_md(pub_relation, EVP_sha1());
			len = SHA_DIGEST_LENGTH;
			break;
		case NID_sha224:
			BIO_set_md(pub_relation, EVP_sha224());
			len = SHA224_DIGEST_LENGTH;
			break;
		case NID_sha256:
			BIO_set_md(pub_relation, EVP_sha256());
			len = SHA256_DIGEST_LENGTH;
			break;
		default:
			printf("Unknown Hash Algorithm Type");
			goto err;
	}

	// Make the hash H(alice||carol)
	hash = (unsigned char *)OPENSSL_malloc(len);
	memcpy(hash, p, len);

	PEM_write_bio_PUBKEY(pub_relation, alice_pub);
	PEM_write_bio_PUBKEY(pub_relation, carol_pub);
	pub_relation_sha = (unsigned char *)OPENSSL_malloc(len);
	BIO_gets(pub_relation, (char *)pub_relation_sha, len);

	// Compare whether they are same
	cmp = CRYPTO_memcmp(pub_relation_sha, hash, len);

	printf("PROGRESS: CMP Result: %d\n", cmp);

	if (cmp != 0)
	{
		printf("PROGRESS: Verify Error. Hash is not matched\n");
		goto verify_err;
	}
	else
	{
		printf("PROGRESS: Verify Success\n");
	}

	OPENSSL_free(hash);

	return 1;

verify_err:
	OPENSSL_free(hash);
err:
	return 0;
}

// Verify the cc request
// Input
//   out: BIO for the standard output
//   request: cc request
//   alice_pub: origin's public key
//   carol_pub: edge's public keky
// Output
//   Success 1, Failure 0
int verify_cc_request(unsigned char *request, EVP_PKEY *alice_pub, EVP_PKEY *carol_pub)
{
	int i;
	size_t len = 0;
	uint16_t sig_type, sig_len;
	unsigned char *p, *cc, *sig;

	printf("PROGRESS: Invoke verify_cc_request()\n");

	p = request;
	n2s(p, len);
	printf("PROGRESS: Length of message: %d\n", (int)len);

	cc = (unsigned char *)OPENSSL_malloc(len);
	memcpy(cc, p, len);
	p += len;
	n2s(p, sig_type);
	printf("PROGRESS: Type of signature: %d\n", sig_type);

	n2s(p, sig_len);
	printf("PROGRESS: Length of signature: %d\n", sig_len);

	sig = (unsigned char *)OPENSSL_malloc(sig_len);
	memcpy(sig, p, sig_len);

	printf("PROGRESS: Signature in verify >>>\n");
	for (i=0; i<sig_len; i++)
	{
		if (i % 10 == 0)
			printf("\n");
		printf("%02X ", sig[i]);
	}
	printf("\n");

	if (!verify_signature(cc, len, sig_type, sig_len, sig, carol_pub))
	{
		printf("ERROR: Verify the signature error\n");
		return 0;
	}
	printf("PROGRESS: Verify the signature success\n");

	// Verify the cc content body
	if (!verify_cc_content_body(cc, alice_pub, carol_pub))
	{
		printf("ERROR: Verify cc content body error\n");
		goto err;
	}

	printf("PROGRESS: Verify cc content body success\n");

	OPENSSL_free(cc);
	OPENSSL_free(sig);

	return 1;

err:
	OPENSSL_free(cc);
	OPENSSL_free(sig);
	return 0;
}

// Verify the cc response
int verify_cc_response(unsigned char *response, EVP_PKEY *alice_pub, EVP_PKEY *carol_pub)
{
	int i;
	size_t len = 0;
	uint16_t sig_type, sig_len;
	unsigned char *p, *request, *sig;

	printf("PROGRESS: Invoke verify_cc_response()\n");

	p = response;
	n2s(p, len);
	printf("PROGRESS: Length of cc_response: %d\n", (int)len);

	request = (unsigned char *)OPENSSL_malloc(len);
	memcpy(request, p, len);
	p += len;
	n2s(p, sig_type);
	printf("PROGRESS: Type of signature: %d\n", sig_type);

	n2s(p, sig_len);
	printf("PROGRESS: Length of signature: %d\n", sig_len);

	sig = (unsigned char *)OPENSSL_malloc(sig_len);
	memcpy(sig, p, sig_len);

	printf("PROGRESS: Signature in verify >>>\n");
	for (i=0; i<sig_len; i++)
	{
		if (i % 10 == 0)
			printf("\n");
		printf("%02X ", sig[i]);
	}
	printf("\n");

	if (!verify_signature(request, len, sig_type, sig_len, sig, alice_pub))
	{
		printf("ERROR: Verify the cc request signature error\n");
		return 0;
	}
	printf("PROGRESS: Verify the cc request signature success\n");

	// Verify the cc content body
	if (!verify_cc_request(request, alice_pub, carol_pub))
	{
		printf("ERROR: Verify cc content body error\n");
		goto err;
	}

	printf("PROGRESS: Verify cc content body success\n");

	OPENSSL_free(request);
	OPENSSL_free(sig);

	return 1;

err:
	OPENSSL_free(request);
	OPENSSL_free(sig);
	return 0;
}

// Verify the signature
// Input
//    out: BIO related to the standard output
//    sig_type: signature algorithm
//    sig_len: the length of the signature
//    sig: signature to be verified
//    pub: public key to be used for the verification
// Output
//    Success 1, Failure 0
int verify_signature(unsigned char *msg, int msg_len, uint16_t sig_type, uint16_t sig_len, unsigned char *sig, EVP_PKEY *pub)
{
	int rc;
	EVP_MD_CTX *ctx;

	ctx = EVP_MD_CTX_create();
	if (ctx == NULL)
	{
		printf("ERROR: EVP_MD_CTX_create error\n");
		return 0;
	}

	// Verify the signature
	switch (sig_type)
	{
		case NID_sha1:
			rc = EVP_DigestVerifyInit(ctx, NULL, EVP_sha1(), NULL, pub);
			break;
		case NID_sha224:
			rc = EVP_DigestVerifyInit(ctx, NULL, EVP_sha224(), NULL, pub);
			break;
		case NID_sha256:
			rc = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub);
			break;
		default:
			printf("ERROR: Unknown Signature Type\n");
	}
	if (rc != 1)
	{
		printf("ERROR: EVP_DigestVerifyInit error\n");
		goto err;
	}

	rc = EVP_DigestVerifyUpdate(ctx, msg, msg_len);
	if (rc != 1)
	{
		printf("ERROR: EVP_DigestVerifyUpdate failed\n");
		goto err;
	}

	rc = EVP_DigestVerifyFinal(ctx, sig, sig_len);
	if (rc != 1)
	{
		printf("ERROR: EVP_DigestVerifyFinal failed\n");
		goto err;
	}
	else
	{
		printf("PROGRESS: Verify Success!\n");
	}

	EVP_MD_CTX_cleanup(ctx);
	return 1;
err:
	EVP_MD_CTX_cleanup(ctx);
	return 0;
}
