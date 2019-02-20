#include "logs.h"
#include "matls.h"
#include "matls_func.h"

int make_keypair(struct keypair **pair, EC_GROUP *group, BN_CTX *ctx) {
  MA_LOG("make keypair");
  BIGNUM *n = BN_new();
  EC_GROUP_get_order(group, n, ctx);

  (*pair) = (struct keypair *)malloc(sizeof(struct keypair));
  (*pair)->pri = BN_new();
  (*pair)->pub = EC_POINT_new(group);

  BN_rand_range((*pair)->pri, n); //private key
  EC_POINT_mul(group, (*pair)->pub, (*pair)->pri, NULL, NULL, ctx); //public key
  BIGNUM *x, *y;
  x = BN_new();
  y = BN_new();
  EC_POINT_get_affine_coordinates_GFp(group, (*pair)->pub, x, y, ctx);

  MA_LOG("end make keypair");
  return 1;
}

int char_to_pub(unsigned char *input, int key_length, EC_POINT *pubkey, EC_GROUP *group, BN_CTX *ctx)
{
  int ret;
  ret = EC_POINT_oct2point(group, pubkey, input, key_length, ctx);
  return 1;
}

int pub_to_char(EC_POINT *secret, unsigned char **secret_str, int *slen, EC_GROUP *group, BN_CTX *ctx)
{
  int key_bytes;

  if (EC_GROUP_get_curve_name(group) == NID_X9_62_prime256v1)
    key_bytes = 256 / 8;
  else
    return -1;

	*slen = 2 * key_bytes + 1;
  (*secret_str) = (unsigned char *)malloc(*slen);
  EC_POINT_point2oct(group, secret, POINT_CONVERSION_UNCOMPRESSED, (*secret_str), (*slen), ctx);

	return 1;
}

int get_index_by_id(SSL *s, unsigned char *id, int idlen)
{
  int ret = -1, nk = s->mb_info->num_keys, i;
  
  for (i=0; i<nk; i++)
  {
    if (!strncmp(s->mb_info->id_table[i], id, idlen))
    {
      ret = i;
      break;
    }
  }

  return ret;
}

unsigned char *get_accountability_key(SSL *s, int index)
{
  return s->mb_info->accountability_keys[index];
}

int generate_accountability_keys(SSL *s)
{
  MA_LOG("Generate Accountability Keys");
  int i, j, l, diff, nk, end, klen, xlen, slen, clen, ilen;
  BIGNUM *x, *y;
  BN_CTX *ctx;
  EC_GROUP *group;
  EC_POINT *secret, *peer_pub;
  unsigned char *secret_str, *srandom, *crandom;

  nk = s->mb_info->num_keys;
  group = s->mb_info->group;

  s->mb_info->accountability_keys = (unsigned char **)calloc(nk, sizeof(unsigned char *));
  s->mb_info->id_table = (unsigned char **)calloc(nk, sizeof(unsigned char *));
  s->mb_info->id_length = (int *)calloc(nk, sizeof(int));

  ctx = BN_CTX_new();
  x = BN_new();
  y = BN_new();

  PRINTK("Server Random", s->mb_info->random[SERVER], s->mb_info->rlen[SERVER]);
  PRINTK("Client Random", s->mb_info->random[CLIENT], s->mb_info->rlen[CLIENT]);

  for (i=0; i<nk; i++)
  {
    unsigned char *id_buf;
    s->mb_info->accountability_keys[i] = (unsigned char *)malloc(SSL_MAX_ACCOUNTABILITY_KEY_LENGTH);
    secret = EC_POINT_new(group);
    peer_pub = EC_POINT_new(group);
    klen = s->mb_info->key_length[i];
    char_to_pub(s->mb_info->peer_str[i], klen, peer_pub, group, ctx);
    EC_POINT_mul(group, secret, NULL, peer_pub, s->mb_info->keypair->pri, ctx);
    EC_POINT_get_affine_coordinates_GFp(group, secret, x, y, ctx);
    xlen = (klen - 1) / 2;
    secret_str = (unsigned char *)malloc(xlen);
    l = BN_bn2bin(x, secret_str);

    if (l < xlen)
    {
      diff = xlen - l;
      for (j=xlen-1; j>=diff; j--)
        secret_str[j] = secret_str[j-diff];
      for (j=diff-1; j>=0; j--)
        secret_str[j] = 0;
    }

    t1_prf(TLS_MD_ACCOUNTABILITY_KEY_CONST, TLS_MD_ACCOUNTABILITY_KEY_CONST_SIZE,
        s->mb_info->random[SERVER], s->mb_info->rlen[SERVER], 
        s->mb_info->random[CLIENT], s->mb_info->rlen[CLIENT], 
        NULL, 0, NULL, 0, secret_str, SECRET_LENGTH, 
        s->mb_info->accountability_keys[i], SSL_MAX_ACCOUNTABILITY_KEY_LENGTH);

    PRINTK("Secret", secret_str, xlen);
    PRINTK("Accountability Key", s->mb_info->accountability_keys[i], 
        SSL_MAX_ACCOUNTABILITY_KEY_LENGTH);

    // Set the identifier of the entity: ID = H(ak)
    // No one can derive ak from H(ak), assuming H() is a secure hash function
    s->mb_info->id_table[i] = (unsigned char *)malloc(TLS_MD_ID_SIZE);
    digest_message(s->mb_info->accountability_keys[i], SSL_MAX_ACCOUNTABILITY_KEY_LENGTH, 
        &id_buf, &ilen);
    s->mb_info->id_length[i] = ilen;
    memcpy(s->mb_info->id_table[i], id_buf, TLS_MD_ID_SIZE);
    free(secret_str);
    free(id_buf);
  }

  for (i=0; i<nk; i++)
  {
    free(s->mb_info->peer_str[i]);
    s->mb_info->peer_str[i] = NULL;
  }

  free(s->mb_info->peer_str);
  s->mb_info->peer_str = NULL;
  free(s->mb_info->key_length);
  s->mb_info->key_length = NULL;

  for (i=0; i<nk; i++)
  {
    MA_LOG("Index: %d", i);
    PRINTK("Generated ID", s->mb_info->id_table[i], s->mb_info->id_length[i]);
  }

  return 1;
}
