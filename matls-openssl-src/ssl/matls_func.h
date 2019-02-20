#include <openssl/ssl.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

int make_keypair(struct keypair **pair, EC_GROUP *group, BN_CTX *ctx);
int char_to_pub(unsigned char *input, int key_length, EC_POINT *pubkey, EC_GROUP *group, BN_CTX *ctx);
int pub_to_char(EC_POINT *secret, unsigned char **secret_str, int *slen, EC_GROUP *group, BN_CTX *ctx);

int get_index_by_id(SSL *s, unsigned char *id, int idlen);
unsigned char *get_accountability_key(SSL *s, int index);
int generate_accountability_keys(SSL *s);
