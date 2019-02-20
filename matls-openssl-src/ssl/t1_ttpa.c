/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/objects.h>
#include "ssl_locl.h"

/* Add the client's cc */
int ssl_add_clienthello_ttpa_ext(SSL *s, unsigned char *p, int *len,
                                        int maxlen)
{
    printf("adding clienthello cc\n");
    return 1;
}

/*
 * Parse the client's cc and abort if it's not right
 */
// This is the function for parsing the ClientHello message from the client
// The purpose is to check the intention of the client
// Input: SSL object, Extension Packet, Alert
// Output: 1 for Success, 0 for Failure
int ssl_parse_clienthello_ttpa_ext(SSL *s, unsigned char *d, int len, int *al)
{
    printf("PROCESSING: CC Length from ClientHello: %d\n", len);
    printf("PROGRESS: CC Length in SSL: %d\n", s->cc_len);
    printf("PROGRESS: CC Length in CTX: %d\n", s->ctx->cc_len);

    // The value of the cc_len must be 0 for the intention
    // If not, it must be error
	
    printf("PROGRESS: Check whether the cc_len is zero\n");
    if (len != 0) {
        *al = SSL_AD_HANDSHAKE_FAILURE;
        return 0;
    }
    printf("PROCESSING: Confirm the cc_len is zero\n");
    
    // From the intention, the server enable the cc mode
	if (s->cc_len > 0)
	{
	    s->ttpa_enabled = 1; // Enable the cc mode
	    printf("PROGRESS: TTPA is enabled\n");
	} 
	else
		printf("PROGRESS: TTPA is not enabled\n");

    return 1;
}

/* Add the server's cc */
// Add the cc extension in the ServerHello message
// If p is 0, it returns the length of the added message in the len
// Input: SSL object, buffer, length to be stored, maximum length
// Output: 1 for Success, 0 for Failure
int ssl_add_serverhello_ttpa_ext(SSL *s, unsigned char *p, int *len,
                                        int maxlen)
{
	CERT_PKEY *orig_cpk;
	unsigned long cert_num;
	int cc_len = SSL_get_cc_len(s);
	printf("INVOKE: SSL GET ORIG SERVER SEND PKEY\n");
	orig_cpk = ssl_get_orig_server_send_pkey(s);
	printf("RETURN: SSL GET ORIG SERVER SEND PKEY\n");

	if (orig_cpk == NULL)
	{
		SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TTPA_EXT,
				SSL_R_ORIG_CERT_LOAD_FAIL);
	}

	printf("INVOKE: SSL3 OUTPUT ORIG CERT CHAIN\n");
	if (!(cert_num = ssl3_output_orig_cert_chain(s, orig_cpk)))
	{
		SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TTPA_EXT,
				SSL_R_ORIG_CERT_TO_BINARY_NOT_WELL);
		return 0;
	}
	printf("RETURN: SSL3 OUTPUT ORIG CERT CHAIN\n");
	printf("VALUE: The length of the origin server's cert: %lu\n", cert_num);

	if (p) {
		unsigned char *cc = SSL_get_cc(s);
		char *orig_cert = SSL_get_orig_certificate_mem(s);

		printf("PROGRESS: Check whether the length exceeds the maxlen\n");
        if ((cc_len + cert_num + 1) > maxlen) {
            SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TTPA_EXT,
                   SSL_R_CC_EXT_TOO_LONG);
            return 0;
        }
		printf("PROGRESS: Confirm the length does not exceed the maxlen\n");

        // The first byte is used to show the length of the cc
		printf("PROGRESS: Insert the cc_len in the packet: %d\n", cc_len);
        //*p = s->cc_len;
        //p++;
		s2n(cc_len, p);
		printf("PROGRESS: Complete inserting the cc_len\n");

        // The next cc_len bytes are used for delivering the cc
		printf("PROGRESS: Insert the cc in the packet\n");
        memcpy(p, cc, cc_len);
        p += cc_len;
		printf("PROGRESS: Complete inserting the cc\n");

		printf("PROGRESS: Insert the origin server's cert\n");
        memcpy(p, orig_cert, cert_num);
		printf("PROGRESS: Complete inserting the origin server's cert\n");
    }

    // The total length of WarrantInfo message is 
    // cc_len (1 byte) + cc (cc_len bytes) + orig_cert (certificate chain bytes + length)
    // Need to check how to find the bytes of the certificates
	printf("PROGRESS: Set the length for the extension\n");
    *len = 2 + cc_len + cert_num;
	printf("PROGRESS: Complete Setting the length for the extension: %d\n", *len);

    return 1;
}

/*
 * Parse the server's cc and abort if it's not right
 */
int ssl_parse_serverhello_ttpa_ext(SSL *s, unsigned char *p, int size, int *al)
{
    printf("ssl_parse_serverhello_ttpa_ext\n");
    int i, l; 
    unsigned long llen, nc, n;
    STACK_OF(X509) *sk = NULL;
    X509 *x = NULL;
    unsigned char *q;
    SESS_CERT *orig;
    EVP_PKEY *pkey = NULL;
 
    if (p == NULL)
    {
        s->ttpa_enabled = 0;
        return 1;
    }

    if (size <= 0)
        return 0;

    n2s(p, s->cc_len);
    s->cc = (unsigned char *)malloc(s->cc_len);
    memcpy(s->cc, p, s->cc_len);

    p += s->cc_len;

    sk = sk_X509_new_null();
    n2l3(p, llen);

    if (llen + 3 != n) {
        *al = SSL_AD_DECODE_ERROR;
        goto f_err;
    }
    for (nc = 0; nc < llen;) {
        if (nc + 3 > llen) {
            *al = SSL_AD_DECODE_ERROR;
            goto f_err;
        }
        n2l3(p, l);
        if ((l + nc + 3) > llen) {
            *al = SSL_AD_DECODE_ERROR;
            goto f_err;
        }

        q = p;
        x = d2i_X509(NULL, &q, l);
        if (x == NULL) {
            *al = SSL_AD_BAD_CERTIFICATE;
            goto f_err;
        }
        if (q != (p + l)) {
            *al = SSL_AD_DECODE_ERROR;
            goto f_err;
        }
        if (!sk_X509_push(sk, x)) {
            goto err;
        }
        x = NULL;
        nc += l + 3;
        p = q;
    }

    i = ssl_verify_cert_chain(s, sk);
    if ((s->verify_mode != SSL_VERIFY_NONE) && (i <= 0)
#ifndef OPENSSL_NO_KRB5
        && !((s->s3->tmp.new_cipher->algorithm_mkey & SSL_kKRB5) &&
             (s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5))
#endif                          /* OPENSSL_NO_KRB5 */
        ) {
        *al = ssl_verify_alarm_type(s->verify_result);
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
               SSL_R_CERTIFICATE_VERIFY_FAILED);
        goto f_err;
    }
    ERR_clear_error();          /* but we keep s->verify_result */

    orig = ssl_sess_cert_new();
    if (orig == NULL)
        goto err;

    if (s->session->sess_orig_cert)
        ssl_sess_cert_free(s->session->sess_orig_cert);
    s->session->sess_orig_cert = orig;

    orig->cert_chain = sk;
    /*
     * Inconsistency alert: cert_chain does include the peer's certificate,
     * which we don't include in s3_srvr.c
     */
    x = sk_X509_value(sk, 0);
    sk = NULL;
    /*
     * VRS 19990621: possible memory leak; sk=null ==> !sk_pop_free() @end
     */

    pkey = X509_get_pubkey(x);

    i = ssl_cert_type(x, pkey);
    s->orig_cert_type = i;

    x = NULL;
    if (0) {
 f_err:
        ssl3_send_alert(s, SSL3_AL_FATAL, *al);
	}
 err:
    EVP_PKEY_free(pkey);
    X509_free(x);
    sk_X509_pop_free(sk, X509_free);

    return 1;
}
