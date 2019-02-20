/* ssl/s3_both.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by 
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#include <limits.h>
#include <string.h>
#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <openssl/logs.h>
#include <stdint.h>

#include "matls.h"
#include "logs.h"

#ifndef OPENSSL_NO_MATLS

int make_signature(unsigned char **sigblk, unsigned char *msg, int msg_len, EVP_PKEY *priv, int nid, int *sigblk_len)
{
	int rc;
	EVP_MD_CTX *ctx;
	unsigned char *sig, *p;
	size_t sig_len;

	ctx = EVP_MD_CTX_create();
	if (ctx == NULL)
	{
		//printf("EVP_MD_CTX_create failed\n");
		goto err;
	}

	// Initialize the md according to nid
	switch (nid)
	{
		case NID_sha256:
			rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv);
			break;
		default:
			//printf("Unknown Hash algorithm\n");
			goto err;
	}

	if (rc != 1)
	{
		//printf("PROGRESS: DigestSign Init Failed\n");
		goto err;
	}

	rc = EVP_DigestSignUpdate(ctx, msg, msg_len);
	if (rc != 1)
	{
		//printf("PROGRESS: DigestSign Update Failed\n");
		goto err;
	}

	rc = EVP_DigestSignFinal(ctx, NULL, &sig_len);
	if (rc != 1)
	{
		//printf("PROGRESS: DigestSign Final Failed\n");
		goto err;
	}
	sig = OPENSSL_malloc(sig_len);

	if (sig == NULL)
	{
		//printf("PROGRESS: OPENSSL_malloc error\n");
		goto err;
	}

	rc = EVP_DigestSignFinal(ctx, sig, &sig_len);
	if (rc != 1)
	{
		//printf("PROGRESS: DigestSign Final Failed\n");
		goto err;
	}

	*sigblk_len = sig_len;
	*sigblk = (unsigned char *)OPENSSL_malloc(*sigblk_len);
	p = *sigblk;
	memcpy(p, sig, sig_len);
	OPENSSL_free(sig);
	EVP_MD_CTX_cleanup(ctx);

	return 1;

err:
	EVP_MD_CTX_cleanup(ctx);

	return 0;
}

int verification(unsigned char *msg, int msg_len, uint16_t sig_type, uint16_t sig_len, unsigned char *sig, EVP_PKEY *pub)
{
  int rc;
  EVP_MD_CTX *ctx;

  ctx = EVP_MD_CTX_create();
  if (ctx == NULL)
  {
    MA_LOG("EVP_MD_CTX_create error");
    return 0;
  }

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
      MA_LOG("Unknown Signature Type");
  }

  if (rc != 1)
  {
    MA_LOG("EVP_DigestVerifyInit error");
    goto err;
  }

  rc = EVP_DigestVerifyUpdate(ctx, msg, msg_len);
  if (rc != 1)
  {
    MA_LOG("EVP_DigestVerifyUpdate failed");
    goto err;
  }

  rc = EVP_DigestVerifyFinal(ctx, sig, sig_len);
  if (rc != 1)
  {
    MA_LOG("EVP_DigestVerifyFinal failed");
    goto err;
  }
  else
    MA_LOG("Verify Success");

  EVP_MD_CTX_cleanup(ctx);
  return 1;
err:
  EVP_MD_CTX_cleanup(ctx);
  return 0;
}

int digest_message(unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{

	EVP_MD_CTX *ctx;

	ctx = EVP_MD_CTX_create();

	if(ctx == NULL)
	{
		//printf("EVP_MD_CTX_create failed\n");
		goto err;
	}
	if(1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
	{
		//printf("EVP_DigestInit failed\n");
		goto err;
	}
	// what is EVP_DigestSignInit in ttpa_func.c
	if(1 != EVP_DigestUpdate(ctx, message, message_len))
	{
		//printf("EVP_DigestUpdate failed\n");
		goto err;
	}
	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
	{
		//printf("OPENSSL_malloc failed\n");
		goto err;
	}
	if(1 != EVP_DigestFinal_ex(ctx, *digest, digest_len))
	{
		//printf("EVP_DigestFinal_ex failed\n");
		goto err;
	}
	EVP_MD_CTX_destroy(ctx);

	return 1;

err:
	EVP_MD_CTX_cleanup(ctx);

	return 0;
}
#endif /* OPENSSL_NO_MATLS */

/* send s->init_buf in records of type 'type' (SSL3_RT_HANDSHAKE or SSL3_RT_CHANGE_CIPHER_SPEC) */
int ssl3_do_write(SSL *s, int type)
	{
	int ret;

	ret=ssl3_write_bytes(s,type,&s->init_buf->data[s->init_off],
	                     s->init_num);
	if (ret < 0) return(-1);
	if (type == SSL3_RT_HANDSHAKE)
		/* should not be done for 'Hello Request's, but in that case
		 * we'll ignore the result anyway */
		ssl3_finish_mac(s,(unsigned char *)&s->init_buf->data[s->init_off],ret);
	
	if (ret == s->init_num)
		{
		if (s->msg_callback)
			s->msg_callback(1, s->version, type, s->init_buf->data, (size_t)(s->init_off + s->init_num), s, s->msg_callback_arg);
		return(1);
		}
	s->init_off+=ret;
	s->init_num-=ret;
	return(0);
	}

int ssl3_send_finished(SSL *s, int a, int b, const char *sender, int slen)
	{
	unsigned char *p,*d;
	int i;
	unsigned long l;

	if (s->state == a)
		{
		d=(unsigned char *)s->init_buf->data;
		p= &(d[4]);

		i=s->method->ssl3_enc->final_finish_mac(s,
			sender,slen,s->s3->tmp.finish_md);
		if (i == 0)
			return 0;
		s->s3->tmp.finish_md_len = i;
		memcpy(p, s->s3->tmp.finish_md, i);
		PRINTK("verify data", s->s3->tmp.finish_md, i);
		p+=i;
		l=i;

                /* Copy the finished so we can use it for
                   renegotiation checks */
                if(s->type == SSL_ST_CONNECT)
                        {
                         OPENSSL_assert(i <= EVP_MAX_MD_SIZE);
                         memcpy(s->s3->previous_client_finished, 
                             s->s3->tmp.finish_md, i);
                         s->s3->previous_client_finished_len=i;
                        }
                else
                        {
                        OPENSSL_assert(i <= EVP_MAX_MD_SIZE);
                        memcpy(s->s3->previous_server_finished, 
                            s->s3->tmp.finish_md, i);
                        s->s3->previous_server_finished_len=i;
                        }

#ifdef OPENSSL_SYS_WIN16
		/* MSVC 1.5 does not clear the top bytes of the word unless
		 * I do this.
		 */
		l&=0xffff;
#endif

		*(d++)=SSL3_MT_FINISHED;
		l2n3(l,d);
		s->init_num=(int)l+4;
		s->init_off=0;

		s->state=b;
		}

	/* SSL3_ST_SEND_xxxxxx_HELLO_B */
	return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
	}

#ifndef OPENSSL_NO_MATLS

int matls_set_parameters(SSL *s, unsigned char *parameters)
{
  int poff, hash_of_ms_length;
  unsigned char hash_of_ms[SHA256_DIGEST_LENGTH];
  EVP_MD_CTX *ctx;
#ifdef DEBUG
  unsigned char *tmp;
#endif /* DEBUG */

  poff = 0;

	/* version (2) */
  parameters[poff++] = s->version >> 8;
  parameters[poff++] = s->version & 0xff;
  PRINTK("Put Version Information", parameters, poff);

	/* ciphersuit (2) */
	ssl3_put_cipher_by_char(s->s3->tmp.new_cipher, &(parameters[poff]));
  poff += MATLS_CIPHERSUITE_LENGTH;
#ifdef DEBUG
  tmp = parameters + poff - MATLS_CIPHERSUITE_LENGTH;
	PRINTK("Put Ciphersuite Information", tmp, 
      MATLS_CIPHERSUITE_LENGTH);
#endif /* DEBUG */

  /* hash of master secret (32) */
  ctx = EVP_MD_CTX_create();
  EVP_DigestInit(ctx, EVP_sha256());
  EVP_DigestUpdate(ctx, s->session->master_key, s->session->master_key_length);
  EVP_DigestFinal(ctx, hash_of_ms, &hash_of_ms_length);
  EVP_MD_CTX_cleanup(ctx);
  memcpy(parameters + poff, hash_of_ms, MATLS_HASH_OF_MASTER_SECRET_LENGTH);
  poff += MATLS_HASH_OF_MASTER_SECRET_LENGTH;
  PRINTK("Put H(ms)", hash_of_ms, MATLS_HASH_OF_MASTER_SECRET_LENGTH);

	/* ti (12) */
	memcpy(parameters + poff, s->s3->tmp.finish_md, MATLS_TRANSCRIPT_LENGTH);
	poff += MATLS_TRANSCRIPT_LENGTH;
  PRINTK("Put Transcript", s->s3->tmp.finish_md, MATLS_TRANSCRIPT_LENGTH);

  PRINTK("Full Parameters", parameters, poff);

  return poff;
}

int matls_send_extended_finished(SSL *s)
{
	unsigned char *p, *d, *pp, *tmp1, *tmp2, *msg, *parameters;
	int i, mlen, slen, plen, tlen, off, poff;
	unsigned long l;
	unsigned char *digest;
	unsigned int digest_len;
	unsigned char *sigblk;
	int sigblk_len;

  off = 0; poff = 0;

	if (s->state == SSL3_ST_SW_EXTENDED_FINISHED_A)
	{
		d =(unsigned char *)s->init_buf->data;
		p = &(d[4]);

    *(d++) = SSL3_MT_EXTENDED_FINISHED;

    mlen = 0, slen = 0;
    if (s->middlebox)
    {
      plen = 2 * MATLS_P_LENGTH;
    }
    else // Server
    {
      plen = MATLS_P_LENGTH;
    }
    MA_LOG("Length of Preset: %d", plen);

    // the buffer to include version, ciphersuite, h(ms), and tls_unique
    parameters = (unsigned char *)malloc(plen);

    poff += matls_set_parameters(s, parameters + poff);
    /* Get the security parameters from another segment */
    if (s->middlebox)
    {
      while (!(s->pair)) {}
      poff += matls_set_parameters(s->pair, parameters);
    }

    MA_LOG("Length of parameters: %d, preset: %d", poff, plen);
		PRINTK("Before HMAC", parameters, poff);

    /* HMAC on parameters */
    if (s->middlebox)
	  {
		  PRINTK("Used Accountability Key", s->mb_info->accountability_keys[((s->server + 1) % 2)], SSL_MAX_ACCOUNTABILITY_KEY_LENGTH);
      digest = HMAC(EVP_sha256(), s->mb_info->accountability_keys[((s->server + 1) % 2)], 
          SSL_MAX_ACCOUNTABILITY_KEY_LENGTH, parameters, plen, NULL, &digest_len);
	  }
    else
	  {
		  PRINTK("Used Accountability Key", s->mb_info->accountability_keys[0], SSL_MAX_ACCOUNTABILITY_KEY_LENGTH);
      digest = HMAC(EVP_sha256(), s->mb_info->accountability_keys[0], 
          SSL_MAX_ACCOUNTABILITY_KEY_LENGTH, parameters, plen, NULL, &digest_len);
	  }

    free(parameters);

	  PRINTK("HMAC", digest, digest_len);

		/* make signature block */
		if (!make_signature(&sigblk, digest, digest_len, (s->cert->key->privatekey), 
          NID_sha256, &sigblk_len))
		{
			MA_LOG("ERROR: make the signature block failed");
			return 0;
		}
		MA_LOG("PROGRESS: make the signature block");

    if (s->middlebox)
    {
      tlen = 2 + TLS_MD_ID_SIZE + MATLS_P_LENGTH + sigblk_len + s->extended_finished_msg_len;
    }
    else
    {
      tlen = 2 + TLS_MD_ID_SIZE + sigblk_len + s->extended_finished_msg_len;
    }

    BUF_MEM_grow(s->init_buf, tlen);
    pp = p;

    /* Put the block length */
    s2n(tlen, p);
    l = 2;

    /* Put the identifier */
    if (s->middlebox)
    {
      memcpy(p, s->mb_info->id_table[((s->server + 1) % 2)], 
          s->mb_info->id_length[((s->server + 1) % 2)]);
      p += s->mb_info->id_length[((s->server + 1) % 2)];
      l += s->mb_info->id_length[((s->server + 1) % 2)];
    }
    else
    {
      memcpy(p, s->mb_info->id_table[0], s->mb_info->id_length[0]);
      p += s->mb_info->id_length[0];
      l += s->mb_info->id_length[0];
    }

    PRINTK("Put the identifier", pp, l);

    /* Put the parameter of another segment */
    if (s->middlebox)
    {
      off = matls_set_parameters(s->pair, p);
      p += off;
      l += off;
      PRINTK("Put the prior parameters", pp, l);
    }

		/* Put the signature block */
		memcpy(p, sigblk, sigblk_len);
    p += sigblk_len;
    l += sigblk_len;
		PRINTK("Put the signature", pp, l);

    /* Append the prior extended messges */
    memcpy(p, s->extended_finished_msg, s->extended_finished_msg_len);
    l += s->extended_finished_msg_len;

		l2n3(l,d); 
		s->init_num=(int)l+4; // total length including the message type
		s->init_off=0;
    s->state = SSL3_ST_SW_EXTENDED_FINISHED_B;
	}

	PRINTK("Extended Finished Message", d, l);

	/* SSL3_ST_SEND_xxxxxx_HELLO_B */
	return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
}

#endif /* OPENSSL_NO_MATLS */

#ifndef OPENSSL_NO_NEXTPROTONEG
/* ssl3_take_mac calculates the Finished MAC for the handshakes messages seen to far. */
static void ssl3_take_mac(SSL *s)
	{
	const char *sender;
	int slen;
	/* If no new cipher setup return immediately: other functions will
	 * set the appropriate error.
	 */
	if (s->s3->tmp.new_cipher == NULL)
		return;
	if (s->state & SSL_ST_CONNECT)
		{
		sender=s->method->ssl3_enc->server_finished_label;
		slen=s->method->ssl3_enc->server_finished_label_len;
		}
	else
		{
		sender=s->method->ssl3_enc->client_finished_label;
		slen=s->method->ssl3_enc->client_finished_label_len;
		}

	s->s3->tmp.peer_finish_md_len = s->method->ssl3_enc->final_finish_mac(s,
		sender,slen,s->s3->tmp.peer_finish_md);
	}
#endif

#ifndef OPENSSL_NO_MATLS
#define MSG_LENGTH 48
/**
 * Find the pointer to the security block according to the identifier
 */
unsigned char *matls_get_block_from_id(SSL *s, unsigned char *ptr, int idx)
{
  // ret: pointer for the return, p: temorary pointer
  // idp: pointer to the identifier in the id table. 
  // idb: pointer to the identifier in the block.
  unsigned char *ret, *p, *idp, *idb;
  int i, nk, len;
  
  nk = s->mb_info->num_keys;
  idp = s->mb_info->id_table[idx];

  for (i=0; i<nk; i++)
  {
    n2s(ptr, len);
    MA_LOG("Length of the block: %d", len);

    idb = ptr;

    if (!CRYPTO_memcmp(idp, idb, TLS_MD_ID_SIZE))
    {
      MA_LOG("Found the pointer");
      return ptr - 2;
    }
    else
    {
      ptr += len;
    }
  }

  MA_LOG("Cannot Found the pointer");
  return NULL;
}

/**
 * Process the extended finished message
 */
int matls_get_extended_finished(SSL *s)
{
	int ok, nk, i, hmlen, moff = 0, slen, rc, len;
	long n;
	unsigned char *p, *q, *sig, *parameters, *hmac = NULL;
  unsigned char *init, *left, *right;
  unsigned char msg[MSG_LENGTH];

#ifdef OPENSSL_NO_NEXTPROTONEG
	/* the mac has already been generated when we received the
	 * change cipher spec message and is in s->s3->tmp.peer_finish_md.
	 */ 
#endif

  MA_LOG("start the function");

	n = s->method->ssl_get_message(s,
		SSL3_ST_CR_EXTENDED_FINISHED_A,
		SSL3_ST_CR_EXTENDED_FINISHED_B,
		SSL3_MT_EXTENDED_FINISHED,
		20000,
		&ok);

	if (!ok) return((int)n);

  RECORD_LOG(s->time_log, MEASURE_1);
	p = (unsigned char *)s->init_msg;

  RECORD_LOG(s->time_log, MEASURE_2);
  if (s->middlebox)
  {
    PRINTK("Simply Forward Extended Finished Message", p, n);
    s->extended_finished_msg = (volatile unsigned char *)malloc(n);
    memcpy(s->extended_finished_msg, p, n);
    s->extended_finished_msg_len = n;
  }
  else // Endpoint (a server or a client)
  {
  RECORD_LOG(s->time_log, MEASURE_3);
    PRINTK("Received Extended Finished Message", p, n);
    q = p;
    init = (unsigned char *)malloc(MATLS_P_LENGTH);

    // Set the initial parameters (client's)
    matls_set_parameters(s, init);

    // Set the left pointer to the initial parameters
    left = init;
    parameters = (unsigned char *)malloc(2 * MATLS_P_LENGTH);

    for (i=0; i<nk-1; i++)
    {
      p = matls_get_block_from_id(s, q, i);
      n2s(p, len);
      p += TLS_MD_ID_SIZE;

      right = p;
      p += MATLS_P_LENGTH;
      memcpy(parameters, left, MATLS_P_LENGTH);
      memcpy(parameters + MATLS_P_LENGTH, right, MATLS_P_LENGTH);

      PRINTK("Before HMAC", parameters, 2 * MATLS_P_LENGTH);
      PRINTK("Used Accountability Key", s->mb_info->accountability_keys[i], SSL_MAX_ACCOUNTABILITY_KEY_LENGTH);
      hmac = HMAC(EVP_sha256(), s->mb_info->accountability_keys[i], SSL_MAX_ACCOUNTABILITY_KEY_LENGTH, msg, moff, NULL, &hmlen);
      PRINTK("HMAC", hmac, hmlen);

      memset(parameters, 0x0, 2 * MATLS_P_LENGTH);

      slen = len - TLS_MD_ID_SIZE - MATLS_P_LENGTH;

      rc = verification(hmac, MATLS_H_LENGTH, NID_sha256, slen, sig, s->mb_info->pkey[i]);
      if (rc != 1)
      {
        printf("HMAC Verify Failed\n");
        MA_LOG1d("Verify Failed", i);
        exit(1);
      }
      sig += slen;
      RECORD_LOG(s->time_log, MEASURE_10);

      left = right;
    }

    free(parameters);
    free(init);
  }

  MA_LOG("end of the function");
	return 1;
}

#endif /* OPENSSL_NO_MATLS */

int ssl3_get_finished(SSL *s, int a, int b)
	{
	int al,i,ok;
	long n;
	unsigned char *p;

#ifdef OPENSSL_NO_NEXTPROTONEG
	/* the mac has already been generated when we received the
	 * change cipher spec message and is in s->s3->tmp.peer_finish_md.
	 */ 
#endif

	n=s->method->ssl_get_message(s,
		a,
		b,
		SSL3_MT_FINISHED,
		20000, /* should actually be 36+4 :-) */
		&ok);

	if (!ok) return((int)n);

	/* If this occurs, we have missed a message */
	if (!s->s3->change_cipher_spec)
		{
		al=SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_GOT_A_FIN_BEFORE_A_CCS);
		goto f_err;
		}
	s->s3->change_cipher_spec=0;

  p = (unsigned char *)s->init_msg;
  i = s->s3->tmp.peer_finish_md_len;

	if (i != n)
		{
		al=SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_BAD_DIGEST_LENGTH);
		goto f_err;
		}

	if (CRYPTO_memcmp(p, s->s3->tmp.peer_finish_md, i) != 0)
		{
		al=SSL_AD_DECRYPT_ERROR;
		SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_DIGEST_CHECK_FAILED);
		goto f_err;
		}

        /* Copy the finished so we can use it for
           renegotiation checks */
        if(s->type == SSL_ST_ACCEPT)
                {
                OPENSSL_assert(i <= EVP_MAX_MD_SIZE);
                memcpy(s->s3->previous_client_finished, 
                    s->s3->tmp.peer_finish_md, i);
                s->s3->previous_client_finished_len=i;
                }
        else
                {
                OPENSSL_assert(i <= EVP_MAX_MD_SIZE);
                memcpy(s->s3->previous_server_finished, 
                    s->s3->tmp.peer_finish_md, i);
                s->s3->previous_server_finished_len=i;
                }

	return(1);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
	return(0);
	}

/* for these 2 messages, we need to
 * ssl->enc_read_ctx			re-init
 * ssl->s3->read_sequence		zero
 * ssl->s3->read_mac_secret		re-init
 * ssl->session->read_sym_enc		assign
 * ssl->session->read_compression	assign
 * ssl->session->read_hash		assign
 */
int ssl3_send_change_cipher_spec(SSL *s, int a, int b)
	{ 
	unsigned char *p;

	if (s->state == a)
		{
		p=(unsigned char *)s->init_buf->data;
		*p=SSL3_MT_CCS;
		s->init_num=1;
		s->init_off=0;

		s->state=b;
		}

	/* SSL3_ST_CW_CHANGE_B */
	return(ssl3_do_write(s,SSL3_RT_CHANGE_CIPHER_SPEC));
	}

static int ssl3_add_cert_to_buf(BUF_MEM *buf, unsigned long *l, X509 *x)
	{
	int n;
	unsigned char *p;

	n=i2d_X509(x,NULL);
	if (!BUF_MEM_grow_clean(buf,(int)(n+(*l)+3)))
		{
		SSLerr(SSL_F_SSL3_ADD_CERT_TO_BUF,ERR_R_BUF_LIB);
		return(-1);
		}
	p=(unsigned char *)&(buf->data[*l]);
	l2n3(n,p);
	i2d_X509(x,&p);
	*l+=n+3;

	return(0);
	}

unsigned long ssl3_output_cert_chain(SSL *s, X509 *x)
	{
	unsigned char *p;
	int i;
	unsigned long l=7;
	BUF_MEM *buf;
	int no_chain;

	if ((s->mode & SSL_MODE_NO_AUTO_CHAIN) || s->ctx->extra_certs)
		no_chain = 1;
	else
		no_chain = 0;

	/* TLSv1 sends a chain with nothing in it, instead of an alert */
	buf=s->init_buf;
	if (!BUF_MEM_grow_clean(buf,10))
		{
		SSLerr(SSL_F_SSL3_OUTPUT_CERT_CHAIN,ERR_R_BUF_LIB);
		return(0);
		}
	if (x != NULL)
		{
		if (no_chain)
			{
			if (ssl3_add_cert_to_buf(buf, &l, x))
				return(0);
			}
		else
			{
			X509_STORE_CTX xs_ctx;

			if (!X509_STORE_CTX_init(&xs_ctx,s->ctx->cert_store,x,NULL))
				{
				SSLerr(SSL_F_SSL3_OUTPUT_CERT_CHAIN,ERR_R_X509_LIB);
				return(0);
				}
			X509_verify_cert(&xs_ctx);
			/* Don't leave errors in the queue */
			ERR_clear_error();
			for (i=0; i < sk_X509_num(xs_ctx.chain); i++)
				{
				x = sk_X509_value(xs_ctx.chain, i);

				if (ssl3_add_cert_to_buf(buf, &l, x))
					{
					X509_STORE_CTX_cleanup(&xs_ctx);
					return 0;
					}
				}
			X509_STORE_CTX_cleanup(&xs_ctx);
			}
		}
	/* Thawte special :-) */
	for (i=0; i<sk_X509_num(s->ctx->extra_certs); i++)
		{
		x=sk_X509_value(s->ctx->extra_certs,i);
		if (ssl3_add_cert_to_buf(buf, &l, x))
			return(0);
		}

	l-=7;
	p=(unsigned char *)&(buf->data[4]);
	l2n3(l,p);
	l+=3;
	p=(unsigned char *)&(buf->data[0]);
	*(p++)=SSL3_MT_CERTIFICATE;
	l2n3(l,p);
	l+=4;
	return(l);
	}

#ifndef OPENSSL_NO_TTPA
unsigned long ssl3_output_orig_cert_chain(SSL *s, X509 *x)
{
	s->orig_cert_buf = BUF_MEM_new();

	int i;
	unsigned long l=7;
	BUF_MEM *buf;
	int no_chain;
	X509_STORE *chain_store;
	chain_store = s->ctx->cert_store;

	if ((s->mode & SSL_MODE_NO_AUTO_CHAIN) || s->ctx->extra_certs)
		no_chain = 1;
	else
		no_chain = 0;

	/* TLSv1 sends a chain with nothing in it, instead of an alert */
	buf=s->orig_cert_buf;
	if (!BUF_MEM_grow_clean(buf,10))
	{
		SSLerr(SSL_F_SSL3_OUTPUT_CERT_CHAIN,ERR_R_BUF_LIB);
		return(0);
	}
	if (x != NULL)
	{
		if (no_chain)
		{
			if (ssl3_add_cert_to_buf(buf, &l, x))
				return(0);
		}
		else
		{
			X509_STORE_CTX xs_ctx;

			if (!X509_STORE_CTX_init(&xs_ctx,chain_store,x,NULL))
			{
				SSLerr(SSL_F_SSL3_OUTPUT_CERT_CHAIN,ERR_R_X509_LIB);
				return(0);
			}
			X509_verify_cert(&xs_ctx);
			/* Don't leave errors in the queue */
			ERR_clear_error();
			for (i=0; i < sk_X509_num(xs_ctx.chain); i++)
			{
				x = sk_X509_value(xs_ctx.chain, i);

				if (ssl3_add_cert_to_buf(buf, &l, x))
				{
					X509_STORE_CTX_cleanup(&xs_ctx);
					return 0;
				}
			}
			X509_STORE_CTX_cleanup(&xs_ctx);
		}
	}
	/* Thawte special :-) */
	for (i=0; i<sk_X509_num(s->ctx->extra_certs); i++)
	{
		x=sk_X509_value(s->ctx->extra_certs,i);
		if (ssl3_add_cert_to_buf(buf, &l, x))
			return(0);
	}

	return(l);
}
#endif /* OPENSSL_NO_TTPA */

#ifndef OPENSSL_NO_MATLS
unsigned long matls_output_cert_chain(SSL *s, X509 *x)
	{
	unsigned char *p;
	int i, nk = 0;
	unsigned long l, init, len_pos, len;
	BUF_MEM *buf;
	int no_chain;

  if (s->middlebox)
  {
    init = l = s->pair->cert_msg_len + 7;
    len_pos = s->pair->cert_msg_len + 4;
  }
  else
    l = 8;

	if ((s->mode & SSL_MODE_NO_AUTO_CHAIN) || s->ctx->extra_certs)
		no_chain = 1;
	else
		no_chain = 0;

	/* TLSv1 sends a chain with nothing in it, instead of an alert */
	buf=s->init_buf;

  if (s->middlebox)
  {
    if (!BUF_MEM_grow_clean(buf, l))
    {
      SSLerr(SSL_F_SSL3_OUTPUT_CERT_CHAIN, ERR_R_BUF_LIB);
      return 0;
    }
    p = &(buf->data[4]);
    memcpy(p, s->pair->cert_msg, s->pair->cert_msg_len);
#ifdef CERT_LOG
    unsigned char *t;
    int num_certs, k, tmp;
    t = p;
    num_certs = *(t++);
    printf("[matls] %s:%s:%d: maximum length of buf: %ld\n", __FILE__, __func__, __LINE__, buf->max);
    printf("[matls] %s:%s:%d: certificate message length to be copied: %d\n", __FILE__, __func__, __LINE__, s->pair->cert_msg_len);
    printf("[matls] %s:%s:%d: # of Certs: %d\n", __FILE__, __func__, __LINE__, num_certs);
    for (k=num_certs; k>1; k--)
    {
      n2l3(t, tmp);
      t += tmp;
      printf("[matls] %s:%s:%d: Length of Certs: %ld\n", __FILE__, __func__, __LINE__, tmp);
    }
    printf("\n");
#endif /* CERT_LOG */
  }
  else
  {
	  if (!BUF_MEM_grow_clean(buf,10))
		{
		  SSLerr(SSL_F_SSL3_OUTPUT_CERT_CHAIN, ERR_R_BUF_LIB);
		  return(0);
		}
  }

	if (x != NULL)
		{
		if (no_chain)
			{
			  if (ssl3_add_cert_to_buf(buf, &l, x))
				  return(0);
			}
		else
			{
			X509_STORE_CTX xs_ctx;

			if (!X509_STORE_CTX_init(&xs_ctx,s->ctx->cert_store,x,NULL))
				{
				SSLerr(SSL_F_SSL3_OUTPUT_CERT_CHAIN,ERR_R_X509_LIB);
				return(0);
				}
			X509_verify_cert(&xs_ctx);
			/* Don't leave errors in the queue */
			ERR_clear_error();
			for (i=0; i < sk_X509_num(xs_ctx.chain); i++)
				{
				x = sk_X509_value(xs_ctx.chain, i);

				if (ssl3_add_cert_to_buf(buf, &l, x))
					{
					X509_STORE_CTX_cleanup(&xs_ctx);
					return 0;
					}
				}
			X509_STORE_CTX_cleanup(&xs_ctx);
			}
		}
	/* Thawte special :-) */
	for (i=0; i<sk_X509_num(s->ctx->extra_certs); i++)
		{
		x=sk_X509_value(s->ctx->extra_certs,i);
		if (ssl3_add_cert_to_buf(buf, &l, x))
			return(0);
		}

	p = (unsigned char *)&(buf->data[4]);
	if (s->middlebox)
	{
    	nk = *p;
    	*(p++) = nk + 1;
  }
  else
  {
    *(p++) = 1;
		l -= 8;
		l2n3(l, p);
		l += 4;
  }

	if (s->middlebox)
	{
		p = (unsigned char *)&(buf->data[len_pos]);
  	len = l - init;
  	l2n3(len, p);
#if defined(DEBUG) || defined(CERT_LOG)
    p = (unsigned char *)&(buf->data[4]);
    printf("\n");
    int cert_idx, num_certs, tlen;
    num_certs = (*p++);
    printf("[matls] %s:%s:%d: # of certs written: %d\n", __FILE__, __func__, __LINE__, num_certs);

    for (cert_idx = num_certs; cert_idx > 0; cert_idx--)
    {
      n2l3(p, tlen);
      p += tlen;
      printf("[matls] %s:%s:%d: Length of Certs written: %d\n", __FILE__, __func__, __LINE__, tlen);
    }

    printf("[matls] %s:%s:%d: position to describe the length: %d\n", __FILE__, __func__, __LINE__, len_pos);
  	printf("[matls] %s:%s:%d: length of the newly added certificate chain: %ld\n", __FILE__, __func__, __LINE__, len);
#endif /* DEBUG */
		l -= 4;
	}

	p = (unsigned char *)&(buf->data[0]);
	*(p++) = SSL3_MT_CERTIFICATE;
	l2n3(l,p);
	l += 4;

#ifdef CERT_LOG
  printf("[matls] %s:%s:%d: total length of certificates: %ld\n", __FILE__, __func__, __LINE__, l);
#endif /* CERT_LOG */

	return(l);
}

#endif /* OPENSSL_NO_MATLS */

/* Obtain handshake message of message type 'mt' (any if mt == -1),
 * maximum acceptable body length 'max'.
 * The first four bytes (msg_type and length) are read in state 'st1',
 * the body is read in state 'stn'.
 */
long ssl3_get_message(SSL *s, int st1, int stn, int mt, long max, int *ok)
	{
	unsigned char *p;
	unsigned long l;
	long n;
	int i,al;

	if (s->s3->tmp.reuse_message)
		{
		s->s3->tmp.reuse_message=0;
		if ((mt >= 0) && (s->s3->tmp.message_type != mt))
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_GET_MESSAGE,SSL_R_UNEXPECTED_MESSAGE);
			goto f_err;
			}
		*ok=1;
		s->init_msg = s->init_buf->data + 4;
		s->init_num = (int)s->s3->tmp.message_size;
		return s->init_num;
		}

	p=(unsigned char *)s->init_buf->data;

	if (s->state == st1) /* s->init_num < 4 */
		{
		int skip_message;

		do
			{

      /*
			/////
      if (mt == SSL3_MT_EXTENDED_FINISHED)
        printf("\n========== Start reading for SSL3_MT_EXTENDED_FINISHED Bottleneck ===========\n");
			st = get_current_microseconds();
			/////
      */
			while (s->init_num < 4)
			{
			  i=s->method->ssl_read_bytes(s,SSL3_RT_HANDSHAKE,
					&p[s->init_num],4 - s->init_num, 0);

				if (i <= 0)
				{
					s->rwstate=SSL_READING;
					*ok = 0;
					return i;
				}
				s->init_num+=i;
			}
			
      /*
			/////
			et = get_current_microseconds();
			if (mt == SSL3_MT_EXTENDED_FINISHED)
			{
				printf("time for read init_num: %lu us\n", et - st);
        printf("========== End reading for SSL3_MT_EXTENDED_FINISHED Bottleneck ===========\n\n");
			}
			/////
      */

			skip_message = 0;
			if (!s->server)
				if (p[0] == SSL3_MT_HELLO_REQUEST)
					/* The server may always send 'Hello Request' messages --
					 * we are doing a handshake anyway now, so ignore them
					 * if their format is correct. Does not count for
					 * 'Finished' MAC. */
					if (p[1] == 0 && p[2] == 0 &&p[3] == 0)
						{
						s->init_num = 0;
						skip_message = 1;

						if (s->msg_callback)
							s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE, p, 4, s, s->msg_callback_arg);
						}
			}
		while (skip_message);

		/* s->init_num == 4 */

		if ((mt >= 0) && (*p != mt))
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_GET_MESSAGE,SSL_R_UNEXPECTED_MESSAGE);
			goto f_err;
			}
		if ((mt < 0) && (*p == SSL3_MT_CLIENT_HELLO) &&
					(st1 == SSL3_ST_SR_CERT_A) &&
					(stn == SSL3_ST_SR_CERT_B))
			{
			/* At this point we have got an MS SGC second client
			 * hello (maybe we should always allow the client to
			 * start a new handshake?). We need to restart the mac.
			 * Don't increment {num,total}_renegotiations because
			 * we have not completed the handshake. */
			ssl3_init_finished_mac(s);
			}

		s->s3->tmp.message_type= *(p++);

		n2l3(p,l);
    /*
		//////
		if (mt == SSL3_MT_EXTENDED_FINISHED)
			printf("length: %lu\n", l);
		/////
    */

		if (l > (unsigned long)max)
			{
			al=SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_GET_MESSAGE,SSL_R_EXCESSIVE_MESSAGE_SIZE);
			goto f_err;
			}
		if (l > (INT_MAX-4)) /* BUF_MEM_grow takes an 'int' parameter */
			{
			al=SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_GET_MESSAGE,SSL_R_EXCESSIVE_MESSAGE_SIZE);
			goto f_err;
			}
		if (l && !BUF_MEM_grow_clean(s->init_buf,(int)l+4))
			{
			SSLerr(SSL_F_SSL3_GET_MESSAGE,ERR_R_BUF_LIB);
			goto err;
			}
		s->s3->tmp.message_size=l;
		s->state=stn;

		s->init_msg = s->init_buf->data + 4;
		s->init_num = 0;
		}

	/* next state (stn) */
	p = s->init_msg;
	n = s->s3->tmp.message_size - s->init_num;

  /*
	/////
	st = get_current_microseconds();
	/////
  */

	while (n > 0)
		{
		i=s->method->ssl_read_bytes(s,SSL3_RT_HANDSHAKE,&p[s->init_num],n,0);
		if (i <= 0)
			{
			s->rwstate=SSL_READING;
			*ok = 0;
			return i;
			}
		s->init_num += i;
		n -= i;
		}

  /*
	/////
	et = get_current_microseconds();
	if (mt == SSL3_MT_EXTENDED_FINISHED)
		printf("time for read bytes: %lu\n", et - st);
	/////
  */

#ifndef OPENSSL_NO_NEXTPROTONEG
	/* If receiving Finished, record MAC of prior handshake messages for
	 * Finished verification. */
	if (*s->init_buf->data == SSL3_MT_FINISHED)
		ssl3_take_mac(s);
#endif

	/* Feed this message into MAC computation. */
  /*
	/////
	st = get_current_microseconds();
	/////
  */
	ssl3_finish_mac(s, (unsigned char *)s->init_buf->data, s->init_num + 4);
  /*
	/////
	et = get_current_microseconds();
	if (mt == SSL3_MT_EXTENDED_FINISHED)
		printf("time for ssl3_finish_mac: %lu\n", et - st);
	/////
  */

	if (s->msg_callback)
		s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE, s->init_buf->data, (size_t)s->init_num + 4, s, s->msg_callback_arg);
	*ok=1;
	return s->init_num;
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	*ok=0;
	return(-1);
	}

int ssl_cert_type(X509 *x, EVP_PKEY *pkey)
	{
	EVP_PKEY *pk;
	int ret= -1,i;

	if (pkey == NULL)
		pk=X509_get_pubkey(x);
	else
		pk=pkey;
	if (pk == NULL) goto err;

	i=pk->type;
	if (i == EVP_PKEY_RSA)
		{
		ret=SSL_PKEY_RSA_ENC;
		}
	else if (i == EVP_PKEY_DSA)
		{
		ret=SSL_PKEY_DSA_SIGN;
		}
#ifndef OPENSSL_NO_EC
	else if (i == EVP_PKEY_EC)
		{
		ret = SSL_PKEY_ECC;
		}	
#endif
	else if (i == NID_id_GostR3410_94 || i == NID_id_GostR3410_94_cc) 
		{
		ret = SSL_PKEY_GOST94;
		}
	else if (i == NID_id_GostR3410_2001 || i == NID_id_GostR3410_2001_cc) 
		{
		ret = SSL_PKEY_GOST01;
		}
err:
	if(!pkey) EVP_PKEY_free(pk);
	return(ret);
	}

int ssl_verify_alarm_type(long type)
	{
	int al;

	switch(type)
		{
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	case X509_V_ERR_UNABLE_TO_GET_CRL:
	case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
		al=SSL_AD_UNKNOWN_CA;
		break;
	case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
	case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
	case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
	case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
	case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_CRL_NOT_YET_VALID:
	case X509_V_ERR_CERT_UNTRUSTED:
	case X509_V_ERR_CERT_REJECTED:
		al=SSL_AD_BAD_CERTIFICATE;
		break;
	case X509_V_ERR_CERT_SIGNATURE_FAILURE:
	case X509_V_ERR_CRL_SIGNATURE_FAILURE:
		al=SSL_AD_DECRYPT_ERROR;
		break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_CRL_HAS_EXPIRED:
		al=SSL_AD_CERTIFICATE_EXPIRED;
		break;
	case X509_V_ERR_CERT_REVOKED:
		al=SSL_AD_CERTIFICATE_REVOKED;
		break;
	case X509_V_ERR_OUT_OF_MEM:
		al=SSL_AD_INTERNAL_ERROR;
		break;
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
	case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
	case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
	case X509_V_ERR_CERT_CHAIN_TOO_LONG:
	case X509_V_ERR_PATH_LENGTH_EXCEEDED:
	case X509_V_ERR_INVALID_CA:
		al=SSL_AD_UNKNOWN_CA;
		break;
	case X509_V_ERR_APPLICATION_VERIFICATION:
		al=SSL_AD_HANDSHAKE_FAILURE;
		break;
	case X509_V_ERR_INVALID_PURPOSE:
		al=SSL_AD_UNSUPPORTED_CERTIFICATE;
		break;
	default:
		al=SSL_AD_CERTIFICATE_UNKNOWN;
		break;
		}
	return(al);
	}

#ifndef OPENSSL_NO_BUF_FREELISTS
/* On some platforms, malloc() performance is bad enough that you can't just
 * free() and malloc() buffers all the time, so we need to use freelists from
 * unused buffers.  Currently, each freelist holds memory chunks of only a
 * given size (list->chunklen); other sized chunks are freed and malloced.
 * This doesn't help much if you're using many different SSL option settings
 * with a given context.  (The options affecting buffer size are
 * max_send_fragment, read buffer vs write buffer,
 * SSL_OP_MICROSOFT_BIG_WRITE_BUFFER, SSL_OP_NO_COMPRESSION, and
 * SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS.)  Using a separate freelist for every
 * possible size is not an option, since max_send_fragment can take on many
 * different values.
 *
 * If you are on a platform with a slow malloc(), and you're using SSL
 * connections with many different settings for these options, and you need to
 * use the SSL_MOD_RELEASE_BUFFERS feature, you have a few options:
 *    - Link against a faster malloc implementation.
 *    - Use a separate SSL_CTX for each option set.
 *    - Improve this code.
 */
static void *
freelist_extract(SSL_CTX *ctx, int for_read, int sz)
	{
	SSL3_BUF_FREELIST *list;
	SSL3_BUF_FREELIST_ENTRY *ent = NULL;
	void *result = NULL;

	CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
	list = for_read ? ctx->rbuf_freelist : ctx->wbuf_freelist;
	if (list != NULL && sz == (int)list->chunklen)
		ent = list->head;
	if (ent != NULL)
		{
		list->head = ent->next;
		result = ent;
		if (--list->len == 0)
			list->chunklen = 0;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
	if (!result)
		result = OPENSSL_malloc(sz);
	return result;
}

static void
freelist_insert(SSL_CTX *ctx, int for_read, size_t sz, void *mem)
	{
	SSL3_BUF_FREELIST *list;
	SSL3_BUF_FREELIST_ENTRY *ent;

	CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
	list = for_read ? ctx->rbuf_freelist : ctx->wbuf_freelist;
	if (list != NULL &&
	    (sz == list->chunklen || list->chunklen == 0) &&
	    list->len < ctx->freelist_max_len &&
	    sz >= sizeof(*ent))
		{
		list->chunklen = sz;
		ent = mem;
		ent->next = list->head;
		list->head = ent;
		++list->len;
		mem = NULL;
		}

	CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
	if (mem)
		OPENSSL_free(mem);
	}
#else
#define freelist_extract(c,fr,sz) OPENSSL_malloc(sz)
#define freelist_insert(c,fr,sz,m) OPENSSL_free(m)
#endif

int ssl3_setup_read_buffer(SSL *s)
	{
	unsigned char *p;
	size_t len,align=0,headerlen;
	
	if (SSL_version(s) == DTLS1_VERSION || SSL_version(s) == DTLS1_BAD_VER)
		headerlen = DTLS1_RT_HEADER_LENGTH;
	else
		headerlen = SSL3_RT_HEADER_LENGTH;

#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
	align = (-SSL3_RT_HEADER_LENGTH)&(SSL3_ALIGN_PAYLOAD-1);
#endif

	if (s->s3->rbuf.buf == NULL)
		{
		len = SSL3_RT_MAX_PLAIN_LENGTH
			+ SSL3_RT_MAX_ENCRYPTED_OVERHEAD
			+ headerlen + align;
		if (s->options & SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER)
			{
			s->s3->init_extra = 1;
			len += SSL3_RT_MAX_EXTRA;
			}
#ifndef OPENSSL_NO_COMP
		if (!(s->options & SSL_OP_NO_COMPRESSION))
			len += SSL3_RT_MAX_COMPRESSED_OVERHEAD;
#endif
		if ((p=freelist_extract(s->ctx, 1, len)) == NULL)
			goto err;
		s->s3->rbuf.buf = p;
		s->s3->rbuf.len = len;
		}

	s->packet= &(s->s3->rbuf.buf[0]);
	return 1;

err:
	SSLerr(SSL_F_SSL3_SETUP_READ_BUFFER,ERR_R_MALLOC_FAILURE);
	return 0;
	}

int ssl3_setup_write_buffer(SSL *s)
	{
	unsigned char *p;
	size_t len,align=0,headerlen;

	if (SSL_version(s) == DTLS1_VERSION || SSL_version(s) == DTLS1_BAD_VER)
		headerlen = DTLS1_RT_HEADER_LENGTH + 1;
	else
		headerlen = SSL3_RT_HEADER_LENGTH;

#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
	align = (-SSL3_RT_HEADER_LENGTH)&(SSL3_ALIGN_PAYLOAD-1);
#endif

	if (s->s3->wbuf.buf == NULL)
		{
		len = s->max_send_fragment
			+ SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD
			+ headerlen + align;
#ifndef OPENSSL_NO_COMP
		if (!(s->options & SSL_OP_NO_COMPRESSION))
			len += SSL3_RT_MAX_COMPRESSED_OVERHEAD;
#endif
		if (!(s->options & SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS))
			len += headerlen + align
				+ SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD;

		if ((p=freelist_extract(s->ctx, 0, len)) == NULL)
			goto err;
		s->s3->wbuf.buf = p;
		s->s3->wbuf.len = len;
		}

	return 1;

err:
	SSLerr(SSL_F_SSL3_SETUP_WRITE_BUFFER,ERR_R_MALLOC_FAILURE);
	return 0;
	}


int ssl3_setup_buffers(SSL *s)
	{
	if (!ssl3_setup_read_buffer(s))
		return 0;
	if (!ssl3_setup_write_buffer(s))
		return 0;
	return 1;
	}

int ssl3_release_write_buffer(SSL *s)
	{
	if (s->s3->wbuf.buf != NULL)
		{
		freelist_insert(s->ctx, 0, s->s3->wbuf.len, s->s3->wbuf.buf);
		s->s3->wbuf.buf = NULL;
		}
	return 1;
	}

int ssl3_release_read_buffer(SSL *s)
	{
	if (s->s3->rbuf.buf != NULL)
		{
		freelist_insert(s->ctx, 1, s->s3->rbuf.len, s->s3->rbuf.buf);
		s->s3->rbuf.buf = NULL;
		}
	return 1;
	}

