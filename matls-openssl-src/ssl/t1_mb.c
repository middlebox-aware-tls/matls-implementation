
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "ssl_locl.h"
#include "tls1.h"
#include "logs.h"
#include "matls.h"

#include <openssl/objects.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#include "matls_func.h"

int handle_parse_errors() {
    //SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_MB_EXT, SSL_R_MB_ENCODING_ERR);
    //*al = SSL_AD_ILLEGAL_PARAMETER;
    printf("Error\n");
    return 0;
}

/* Add the client's mb */
int ssl_add_clienthello_mb_ext(SSL *s, unsigned char *p, int *len,
        int maxlen)
{
    MA_LOG("adding clienthello mb");

    int group_id, num_keys, pub_length, ext_len, plen;
    unsigned char *pub_str;

    s->mb_enabled = 0;

    if (p)
    {
      group_id = s->mb_info->group_id;
      pub_str = s->mb_info->pub_str;
      pub_length = s->mb_info->pub_length;

      ////RECORD_LOG(s->time_log, CLIENT_CLIENT_HELLO_1S);
      if (s->middlebox)
      {
        MA_LOG("Before waiting the message");
	      MSTART("Before waiting the message from the client", "server-side");
        while (!(s->pair && s->pair->extension_from_clnt_msg && (s->pair->extension_from_clnt_msg_len > 0))) { __sync_synchronize(); }
#ifdef STEP_CHECK
        printf("[step] after receiving extension message from the client: %lu\n", get_current_microseconds());
#endif /* STEP_CHECK */
	      MEND("After waiting the message from the client", "server-side");
        MA_LOG("The client side pair has the extension message");
        MA_LOG1d("before memcpy", s->pair->extension_from_clnt_msg_len);
        plen = s->pair->extension_from_clnt_msg_len;
        memcpy(p, s->pair->extension_from_clnt_msg, plen);
        free(s->pair->extension_from_clnt_msg);

        n2s(p, ext_len);
        p -= 2;
        ext_len = ext_len + TYPE_LENGTH + META_LENGTH + pub_length;
        s2n(ext_len, p);
        p += 2; // Group ID
        num_keys = *p;
        MA_LOG1d("before number of keys", (int)*p);
        *p = num_keys + 1;
        MA_LOG1d("after number of keys", (int)*p);
        p++;
        p += plen - 5;

        if (s->server_side)
        {
          *p = TYPE_SERVER_SIDE;
          p++;
//          *len = plen + TYPE_LENGTH + META_LENGTH + pub_length + META_LENGTH + s->proof_length;
          *len = plen + TYPE_LENGTH + META_LENGTH + pub_length;
        }
        else
        {
          *p = TYPE_CLIENT_SIDE;
          p++;
          *len = plen + TYPE_LENGTH + META_LENGTH + pub_length;
        }
        s2n(pub_length, p);
        MA_LOG1d("Added Public Key Length", pub_length);
        memcpy(p, pub_str, pub_length);
        p += pub_length;

        MA_LOG1d("s->pair->extension_from_clnt_msg_len", plen);
        MA_LOG1d("length of client hello extension", *len);
      }
      else // Client
      {
        s->mb_info->random[CLIENT] = s->mb_info->pub_str;
        s->mb_info->rlen[CLIENT] = s->mb_info->pub_length;
        ext_len = GROUP_ID_LENGTH + NUM_OF_KEYS_INFO + TYPE_LENGTH + META_LENGTH + pub_length;
        MA_LOG1d("Extension Length", ext_len);
        s2n(ext_len, p);
        MA_LOG1d("Group ID", s->mb_info->group_id);
        s2n(s->mb_info->group_id, p);
        *(p++) = 1;
        *(p++) = TYPE_CLIENT;
        s2n(pub_length, p);
        memcpy(p, pub_str, pub_length);
        *len = ext_len + 2;
      }
      ////RECORD_LOG(s->time_log, CLIENT_CLIENT_HELLO_1E);
      //INTERVAL(s->time_log, CLIENT_CLIENT_HELLO_1S, CLIENT_CLIENT_HELLO_1E);
    }

    return 1;
}

/*
 * Parse the client's mb and abort if it's not right
 */
// This is the function for parsing the ClientHello message from the client
// The purpose is to check the intention of the client
// Input: SSL object, Extension Packet, Alert
// Output: 1 for Success, 0 for Failure
int ssl_parse_clienthello_mb_ext(SSL *s, unsigned char *d, int len, int *al)
{
    unsigned char *p, *peer_str;
    int i, j, diff, slen, klen, nk, l, xlen, end, type;  
    // klen: key length, nk: number of keys, plen: EC point length

    MA_LOG1d("Read the mb length from the extension packet", len);

    if(len < 1)
    {
        return handle_parse_errors();
    }

    ////RECORD_LOG(s->time_log, SERVER_CLIENT_HELLO_1S);
    if (s->middlebox)
    {
      MA_LOG("Copy this extension message to my SSL struct (not to pair)");
      s->extension_from_clnt_msg = (volatile unsigned char *)malloc(len);
      memcpy(s->extension_from_clnt_msg, d, len);
      s->extension_from_clnt_msg_len = len;
    }
    ////RECORD_LOG(s->time_log, SERVER_CLIENT_HELLO_1E);
    //INTERVAL(s->time_log, SERVER_CLIENT_HELLO_1S, SERVER_CLIENT_HELLO_1E);

    ////RECORD_LOG(s->time_log, SERVER_CLIENT_HELLO_2S);
    p = d;
#ifdef DEBUG
    int ext_len;
    n2s(p, ext_len);
    MA_LOG1d("Received Extension Length", ext_len);
#else
    p += 2;
#endif /* DEBUG */

    /* message: group_id(2bytes) + num_keys(1byte) + (key length(1byte) and key value) list */

    n2s(p,s->mb_info->group_id);
    MA_LOG1d("Group ID", s->mb_info->group_id);

    /* Check num_keys */
    if (s->middlebox)
    {
      nk = s->mb_info->num_keys = 2;
      p += 1;
    }
    else
      nk = s->mb_info->num_keys = *(p++);

    MA_LOG1d("Number of Keys (nk)", nk);
    ////RECORD_LOG(s->time_log, SERVER_CLIENT_HELLO_2E);
    //INTERVAL(s->time_log, SERVER_CLIENT_HELLO_2S, SERVER_CLIENT_HELLO_2E);

    ////RECORD_LOG(s->time_log, SERVER_CLIENT_HELLO_3S);
    if (s->middlebox) // middlebox, index 0: client->server, index 1: server->client
      nk = 2;
    s->mb_info->key_length = (int *)calloc(nk, sizeof(int));
    s->mb_info->peer_str = (volatile unsigned char **)calloc(nk, sizeof(unsigned char *));
    ////RECORD_LOG(s->time_log, SERVER_CLIENT_HELLO_3E);
    //INTERVAL(s->time_log, SERVER_CLIENT_HELLO_3S, SERVER_CLIENT_HELLO_3E);

    ////RECORD_LOG(s->time_log, SERVER_CLIENT_HELLO_4S);
    if(nk < 1)
    {
        return handle_parse_errors();
    }

    if (s->middlebox)
      end = 1;
    else
      end = nk;
    ////RECORD_LOG(s->time_log, SERVER_CLIENT_HELLO_4E);
    //INTERVAL(s->time_log, SERVER_CLIENT_HELLO_4S, SERVER_CLIENT_HELLO_4E);

    ////RECORD_LOG(s->time_log, SERVER_CLIENT_HELLO_5S);
    for (i=0; i<end; i++)
    {
      type = *(p++);
/*
      if (type != TYPE_CLIENT_SIDE)
      {
        MA_LOG1d("Wrong Type", type);
      }
*/
      n2s(p, klen);

      if (s->middlebox)
      {
        s->mb_info->key_length[CLIENT] = klen;
        s->mb_info->peer_str[CLIENT] = (unsigned char *)malloc(klen);
        memcpy(s->mb_info->peer_str[CLIENT], p, klen);
      }
      else
      {
        s->mb_info->key_length[i] = klen;
        s->mb_info->peer_str[i] = (unsigned char *)malloc(klen);
        memcpy(s->mb_info->peer_str[i], p, klen);
      }
      p += klen;
    }

    if (s->middlebox)
    {
      s->mb_info->random[CLIENT] = s->mb_info->peer_str[CLIENT];
      s->mb_info->rlen[CLIENT] = s->mb_info->key_length[CLIENT];
    }
    else
    {
      s->mb_info->random[CLIENT] = s->mb_info->peer_str[0];
      s->mb_info->rlen[CLIENT] = s->mb_info->key_length[0];
    }

    ////RECORD_LOG(s->time_log, SERVER_CLIENT_HELLO_5E);
    //INTERVAL(s->time_log, SERVER_CLIENT_HELLO_5S, SERVER_CLIENT_HELLO_5E);

    s->mb_enabled = 1; // Enable the mb mode
    MA_LOG("MB Extension is enabled");

    return 1;
}

/* Add the server's mb */
// Add the mb extension in the ServerHello message
// If p is 0, it returns the length of the added message in the len
// Input: SSL object, buffer, length to be stored, maximum length
// Output: 1 for Success, 0 for Failure
int ssl_add_serverhello_mb_ext(SSL *s, unsigned char *p, int *len,
        int maxlen)
{
    // group_id (2 bytes) + num_keys (1 byte) + pubkey_len (1 byte) + pubkey (pubkey_len bytes)
  MA_LOG("adding serverhello mb");

  int i, group_id, num_keys, pub_length, ext_len, plen;
  unsigned char *pub_str;

  if (p) 
  {
    group_id = s->mb_info->group_id;
    num_keys = 1;
    pub_length = s->mb_info->pub_length;
    pub_str = s->mb_info->pub_str;

    //RECORD_LOG(s->time_log, SERVER_SERVER_HELLO_2S);
    if (s->middlebox)
    {
      MA_LOG("Before waiting the message");
      MSTART("Before waiting the message", "client-side");
      while (!(s->pair && (s->pair->extension_from_srvr_msg_len > 0))) { __sync_synchronize(); }
#ifdef STEP_CHECK
      printf("[step] after receiving extension message from the server: %lu\n", get_current_microseconds());
#endif /* STEP_CHECK */
      MEND("The server side pair has the extension message", "client-side");
      MA_LOG("The server side pair has the extension message");
      MA_LOG1d("before memcpy", s->pair->extension_from_srvr_msg_len);
      plen = s->pair->extension_from_srvr_msg_len;
      memcpy(p, s->pair->extension_from_srvr_msg, plen);
      free(s->pair->extension_from_srvr_msg);

      n2s(p, ext_len);
      p -= 2;
	    if (s->server_side)
		    ext_len = ext_len + TYPE_LENGTH + META_LENGTH + pub_length + META_LENGTH + s->proof_length;
	    else
      	ext_len = ext_len + TYPE_LENGTH + META_LENGTH + pub_length;
      s2n(ext_len, p);
      p += 2;
      num_keys = *p;
      *p = num_keys + 1;
      p++;
      p += plen - 5;

	    if (s->server_side)
	    {
		    *p = TYPE_SERVER_SIDE;
		    p++;
		    *len = plen + TYPE_LENGTH + META_LENGTH + pub_length + META_LENGTH + s->proof_length;
	    }
	    else
	    {
		    *p = TYPE_CLIENT_SIDE;
		    p++;
		    *len = plen + TYPE_LENGTH + META_LENGTH + pub_length;
	    }
      s2n(pub_length, p);
      memcpy(p, pub_str, pub_length);
	    p += pub_length;

	    if (s->server_side)
	    {
		    s2n(s->proof_length, p);
		    memcpy(p, s->proof, s->proof_length);
	    }
    }
    else // Server
    {
      s->mb_info->random[SERVER] = s->mb_info->pub_str;
      s->mb_info->rlen[SERVER] = s->mb_info->pub_length;
      ext_len = META_LENGTH + 1 + TYPE_LENGTH + META_LENGTH + pub_length;
      s2n(ext_len, p);
	    s2n(group_id, p);
	    *(p++) = num_keys;
	    *(p++) = TYPE_SERVER;
	    s2n(pub_length, p); //pubkey_len
	    memcpy(p, pub_str, pub_length); //pubkey
      p += pub_length;
      *len = META_LENGTH + META_LENGTH + 1 + TYPE_LENGTH + META_LENGTH + pub_length;
	  }
    //RECORD_LOG(s->time_log, SERVER_SERVER_HELLO_2E);
    //INTERVAL(s->time_log, SERVER_SERVER_HELLO_2S, SERVER_SERVER_HELLO_2E);
  }

  return 1;
}

/*
 * Parse the server's mb and abort if it's not right
 */
int ssl_parse_serverhello_mb_ext(SSL *s, unsigned char *d, int size, int *al)
{
  unsigned char *p, *peer_str;
  int i, j, diff, klen, nk, type, xlen, plen, len, end;
  SSL *tmp;

  //RECORD_LOG(s->time_log, CLIENT_SERVER_HELLO_1S);
  if (size < 0)
  {
    return handle_parse_errors();
  }

  if (s->middlebox)
  {
    MA_LOG1d("Before malloc for extension from srvr msg", size);
    s->extension_from_srvr_msg = (volatile unsigned char *)malloc(size);
    memcpy(s->extension_from_srvr_msg, d, size);
    s->extension_from_srvr_msg_len = size;
  }

  if (s->middlebox)
    tmp = s->pair;
  else // Client
    tmp = s;

  p = d;
#ifdef DEBUG
  int ext_len;
  n2s(p, ext_len);
  MA_LOG1d("Received Extension Length", ext_len);
#else
  p += 2;
#endif /* DEBUG */

  n2s(p, s->mb_info->group_id);
  MA_LOG1d("Received Group ID", s->mb_info->group_id);

  if (s->middlebox)
  {
    nk = s->mb_info->num_keys = 2;
    p += 1;
  }
  else
    nk = s->mb_info->num_keys = *(p++);

  MA_LOG1d("Number of Keys", nk);
  //RECORD_LOG(s->time_log, CLIENT_SERVER_HELLO_1E);
  //INTERVAL(s->time_log, CLIENT_SERVER_HELLO_1S, CLIENT_SERVER_HELLO_1E);

  //RECORD_LOG(s->time_log, CLIENT_SERVER_HELLO_2S);
  if (s->middlebox)
    end = 1;
  else // Client
  {
    end = nk;
    tmp->mb_info->key_length = (int *)calloc(nk, sizeof(int));
    tmp->mb_info->peer_str = (volatile unsigned char **)calloc(nk, sizeof(unsigned char *));
    tmp->mb_info->accountability_keys = (unsigned char **)calloc(nk, sizeof(unsigned char *));
    tmp->mb_info->type = (unsigned char *)calloc(nk, sizeof(unsigned char));
    tmp->mb_info->proof = (unsigned char **)calloc(nk, sizeof(unsigned char *));
    tmp->mb_info->proof_length = (int *)calloc(nk, sizeof(int));

    for (i=0; i<nk; i++)
    {
      tmp->mb_info->accountability_keys[i] = 
        (unsigned char *)malloc(SSL_MAX_ACCOUNTABILITY_KEY_LENGTH);
      tmp->mb_info->proof[i] = NULL;
      tmp->mb_info->proof_length[i] = 0;
    }
    
  }
  //RECORD_LOG(s->time_log, CLIENT_SERVER_HELLO_2E);
  //INTERVAL(s->time_log, CLIENT_SERVER_HELLO_2S, CLIENT_SERVER_HELLO_2E);

  //RECORD_LOG(s->time_log, CLIENT_SERVER_HELLO_3S);

  for (i=0; i<end; i++)
  {
    type = *(p++);

    MA_LOG1d("Received Type", type);
    n2s(p, klen);
    MA_LOG1d("Received Key Length", klen);

    if (s->middlebox)
    {
      tmp->mb_info->key_length[SERVER] = klen;
      tmp->mb_info->peer_str[SERVER] = (unsigned char *)malloc(klen);
      memcpy(tmp->mb_info->peer_str[SERVER], p, klen);
    }
    else // Client
    {
      tmp->mb_info->key_length[i] = klen;
      tmp->mb_info->peer_str[i] = (unsigned char *)malloc(klen);
      memcpy(tmp->mb_info->peer_str[i], p, klen);
    }
    p += klen;
    PRINTK("Received DH Share", tmp->mb_info->peer_str[i], klen);

    switch (type)
    {
      case TYPE_CLIENT_SIDE:
        break;
      case TYPE_SERVER_SIDE:
        n2s(p, plen);
        tmp->mb_info->proof_length[i] = plen;
        tmp->mb_info->proof[i] = (unsigned char *)malloc(plen);
        memcpy(tmp->mb_info->proof[i], p, plen);
        tmp->mb_info->proof_length[i] = plen;
        p += plen;
        break;
      default:
        MA_LOG("Wrong Type");
    }
  }

  if (s->middlebox)
  {
    tmp->mb_info->random[SERVER] = tmp->mb_info->peer_str[SERVER];
    tmp->mb_info->rlen[SERVER] = tmp->mb_info->key_length[SERVER];
  }
  else
  {
    tmp->mb_info->random[SERVER] = tmp->mb_info->peer_str[0];
    tmp->mb_info->rlen[SERVER] = tmp->mb_info->key_length[0];
  }

  //RECORD_LOG(s->time_log, CLIENT_SERVER_HELLO_3E);
  //INTERVAL(s->time_log, CLIENT_SERVER_HELLO_3S, CLIENT_SERVER_HELLO_3E);

  s->mb_enabled = 1;

  MA_LOG("Finished Serverhello Extension");

  return 1;
}
