#include "mssl.h"
#include "table.h"
#include "common.h"

void handle_error(const char *file, int lineno, const char *msg) {
  fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
  ERR_print_errors_fp(stderr);
  exit(1);
}

#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

void die(const char *msg) {
  perror(msg);
  exit(1);
}

void print_unencrypted_data(char *buf, size_t len) {
  printf("%.*s", (int)len, buf);
}

int send_to_pair(SSL *ssl, char *buf, size_t len)
{
  MA_LOG("Send the following data to the pair");
  int ret = 0;
#ifdef DEBUG
  printf("%.*s", (int)len, buf);
#endif /* DEBUG */

  while (!ssl->pair) {}

  do {
    ret += SSL_write(ssl->pair, buf, len);
  } while (ret < len);

  MA_LOG1d("Sent bytes", ret);
  return ret;
}

void ssl_client_init(struct ssl_client *p)
{
  memset(p, 0, sizeof(struct ssl_client));

  p->rbio = BIO_new(BIO_s_mem());
  p->wbio = BIO_new(BIO_s_mem());

  p->ssl = SSL_new(ctx);
  //p->ssl->lock = (int *)calloc(1, sizeof(int));

  SSL_set_accept_state(p->ssl); /* sets ssl to work in server mode. */
  SSL_set_bio(p->ssl, p->rbio, p->wbio);

  p->io_on_read = send_to_pair;
}

void ssl_client_cleanup(struct ssl_client *p)
{
  SSL_free(p->ssl);   /* free the SSL object and its BIO's */
  free(p->write_buf);
  free(p->encrypt_buf);
}

int ssl_client_want_write(struct ssl_client *cp) {
  return (cp->write_len>0);
}

static enum sslstatus get_sslstatus(SSL* ssl, int n)
{
  switch (SSL_get_error(ssl, n))
  {
    case SSL_ERROR_NONE:
      return SSLSTATUS_OK;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
      return SSLSTATUS_WANT_IO;
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    default:
      return SSLSTATUS_FAIL;
  }
}

void send_unencrypted_bytes(const char *buf, size_t len)
{
  client.encrypt_buf = (char*)realloc(client.encrypt_buf, client.encrypt_len + len);
  memcpy(client.encrypt_buf+client.encrypt_len, buf, len);
  client.encrypt_len += len;
}

void queue_encrypted_bytes(const char *buf, size_t len)
{
  client.write_buf = (char*)realloc(client.write_buf, client.write_len + len);
  memcpy(client.write_buf+client.write_len, buf, len);
  client.write_len += len;
}

int on_read_cb(char* src, size_t len)
{
  char buf[DEFAULT_BUF_SIZE];
  enum sslstatus status;
  int n;
  //printf("len: %lu\n", len);

  while (len > 0) {
    n = BIO_write(client.rbio, src, len);
    //printf("after BIO_write: %d\n", n);

    if (n<=0)
      return -1; /* if BIO write fails, assume unrecoverable */

    src += n;
    len -= n;

    if (!SSL_is_init_finished(client.ssl)) {
      n = SSL_accept(client.ssl);
      //printf("after accept: %d\n", n);
      status = get_sslstatus(client.ssl, n);

      /* Did SSL request to write bytes? */
      if (status == SSLSTATUS_WANT_IO)
        do {
          n = BIO_read(client.wbio, buf, sizeof(buf));
          //printf("after BIO_read: %d\n", n);
          if (n > 0)
            queue_encrypted_bytes(buf, n);
          else if (!BIO_should_retry(client.wbio))
            return -1;
        } while (n>0);

      if (status == SSLSTATUS_FAIL)
        return -1;

      //printf("SSL_is_init_finished accept: %d\n", SSL_is_init_finished(client.ssl));
      if (!SSL_is_init_finished(client.ssl))
        return 0;
    }

    /* The encrypted data is now in the input bio so now we can perform actual
     * read of unencrypted data. */

    do {
      n = SSL_read(client.ssl, buf, sizeof(buf));
      //printf("SSL_read bytes: %d\n", n);
      if (n > 0)
        client.io_on_read(client.ssl, buf, (size_t)n);
    } while (n > 0);

    status = get_sslstatus(client.ssl, n);

    if (status == SSLSTATUS_WANT_IO)
      do {
        n = BIO_read(client.wbio, buf, sizeof(buf));
        if (n > 0)
          queue_encrypted_bytes(buf, n);
        else if (!BIO_should_retry(client.wbio))
          return -1;
      } while (n>0);

    if (status == SSLSTATUS_FAIL)
      return -1;
  }
  return 0;
}
int do_encrypt()
{
  char buf[DEFAULT_BUF_SIZE];
  enum sslstatus status;

  if (!SSL_is_init_finished(client.ssl))
    return 0;

  while (client.encrypt_len>0) {
    int n = SSL_write(client.ssl, client.encrypt_buf, client.encrypt_len);
    status = get_sslstatus(client.ssl, n);

    if (n>0) {
      /* consume the waiting bytes that have been used by SSL */
      if ((size_t)n<client.encrypt_len)
        memmove(client.encrypt_buf, client.encrypt_buf+n, client.encrypt_len-n);
      client.encrypt_len -= n;
      client.encrypt_buf = (char*)realloc(client.encrypt_buf, client.encrypt_len);

      /* take the output of the SSL object and queue it for socket write */
      do {
        n = BIO_read(client.wbio, buf, sizeof(buf));
        if (n > 0)
          queue_encrypted_bytes(buf, n);
        else if (!BIO_should_retry(client.wbio))
          return -1;
      } while (n>0);
    }

    if (status == SSLSTATUS_FAIL)
      return -1;

    if (n==0)
      break;
  }
  return 0;
}

int do_sock_read()
{
  char buf[DEFAULT_BUF_SIZE];
  ssize_t n = read(client.fd, buf, sizeof(buf));
  if (n>0)
    return on_read_cb(buf, (size_t)n);
  else
    return -1;
}

/* Write encrypted bytes to the socket. */
int do_sock_write()
{
  ssize_t n = write(client.fd, client.write_buf, client.write_len);
  //printf("after write: %lu\n", n);
  if (n>0) {
    if ((size_t)n<client.write_len)
      memmove(client.write_buf, client.write_buf+n, client.write_len-n);
    client.write_len -= n;
    client.write_buf = (char*)realloc(client.write_buf, client.write_len);
    return 0;
  }
  else
    return -1;
}

void sni_callback(unsigned char *buf, int len, SSL *ssl)
{
  //printf("sni_callback\n");
  int index, ilen, port, rc, tidx;
  unsigned char *ip; 
  void *status;
  struct forward_info *args;
  
  //printf("server name: %s\n", buf);
  index = find_by_name(buf, len);
  ip = get_ip_by_index(index);
  port = get_port_by_index(index);
  //printf("forward to: %s:%d\n", ip, port);

  args = (struct forward_info *)malloc(sizeof(struct forward_info));
  args->index = index;
  args->ssl = ssl;
  tidx = get_thread_index();
  MA_LOG1d("tidx after get_thread_index() in sni_callback", tidx);
  rc = pthread_create(&threads[tidx], &attr, run, args);
  if (rc < 0)
  {
    MA_LOG("error in pthread create");
    exit(EXIT_FAILURE);
  }
}

void msg_callback(int write, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
  int i;
  unsigned char *p;
  p = (unsigned char *)buf;

  //printf("write operation? %d\n", write);
  //printf("version? 0x%x\n", version);
  //printf("content type? ");
/*
  switch(content_type)
  {
    case 20:
      printf("change cipher spec\n");
      break;
    case 21:
      printf("alert\n");
      break;
    case 22:
      printf("handshake\n");
      break;
    case 23:
      printf("application data\n");
      break;
    default:
      printf("invalid\n");
  }
*/
/*
  for (i=0; i<len; i++)
  {
    printf("%02X ", p[i]);
    if (i % 8 == 7)
      printf("\n");
  }
  printf("\n");
*/
}

void *run(void *data)
{
  struct forward_info *args;
  struct timeval tv;
  unsigned char *ip;
  unsigned char buf[DEFAULT_BUF_SIZE];
  unsigned char *server_name;  
  int server, port, ret, rcvd, sent;
  SSL *ssl, *pair;
  fd_set reads, temps;

  args = (struct forward_info *)data;
  ip = get_ip_by_index(args->index);
  port = get_port_by_index(args->index);
  server_name = get_name_by_index(args->index);

  server = open_connection(ip, port);
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  SSL_set_tlsext_host_name(ssl, server_name);
  
  MA_LOG1s("Start SSL connections to", ip);

  MA_LOG1p("ssl", ssl);
  MA_LOG1p("args->ssl", args->ssl);
  MA_LOG1p("ssl->pair", ssl->pair);
  MA_LOG1p("args->ssl->pair", args->ssl->pair);
  SSL_set_pair(ssl, args->ssl);
  MA_LOG1p("ssl", ssl);
  MA_LOG1p("args->ssl", args->ssl);
  MA_LOG1p("ssl->pair", ssl->pair);
  MA_LOG1p("args->ssl->pair", args->ssl->pair);

#ifdef MATLS
  SSL_enable_mb(ssl);
  MA_LOG1d("matls enabled", ssl->mb_enabled);
#else
  SSL_disable_mb(ssl);
  MA_LOG1d("matls disabled", ssl->mb_enabled);
#endif

  ssl->time_log = args->ssl->time_log;
  unsigned long start, end;

  start = get_current_microseconds();
  if ((ret = SSL_connect(ssl)) != 1)
  {
    ERR_print_errors_fp(stderr);
    MA_LOG1s("Failed to connect to", ip);
    MA_LOG1d("SSL_connect()", ret);
    MA_LOG1d("SSL_get_error()", SSL_get_error(ssl, ret));
  }
  else
  {
    end = get_current_microseconds();
    MA_LOG1s("Succeed to connect to", ip);
    MA_LOG1lu("SSL_connect time", end - start);
  }
}

void ssl_init(char *cert, char *priv) {
  //printf("initialising SSL\n");

  /* SSL library initialisation */
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  /* create the SSL server context */
  ctx = SSL_CTX_new(TLSv1_2_method());
  if (!ctx)
    die("SSL_CTX_new()");

  /* Load certificate and private key files, and check consistency  */
  int err;
  err = SSL_CTX_use_certificate_file(ctx, cert,  SSL_FILETYPE_PEM);
  if (err != 1)
    int_error("SSL_CTX_use_certificate_file failed");
  else
  {
#ifdef DEBUG
    printf("certificate file loaded ok\n");
#endif /* DEBUG */
  }

  /* Indicate the key file to be used */
  err = SSL_CTX_use_PrivateKey_file(ctx, priv, SSL_FILETYPE_PEM);
  if (err != 1)
    int_error("SSL_CTX_use_PrivateKey_file failed");
  else
  {
#ifdef DEBUG
    printf("private-key file loaded ok\n");
#endif /* DEBUG */
  }

  /* Make sure the key and certificate file match. */
  if (SSL_CTX_check_private_key(ctx) != 1)
    int_error("SSL_CTX_check_private_key failed");
  else
  {
#ifdef DEBUG
    printf("private key verified ok\n");
#endif /* DEBUG */
  }

  /* Recommended to avoid SSLv2 & SSLv3 */
  SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
  //SSL_CTX_set_msg_callback(ctx, msg_callback);
  SSL_CTX_set_sni_callback(ctx, sni_callback);
  SSL_CTX_enable_mb(ctx);
}

void init_thread_config(void)
{
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
}

int get_thread_index(void)
{
  int i, ret = -1;

  for (i=0; i<MAX_THREADS; i++)
    if (!threads[i])
    {
      ret = i;
      break;
    }

  return ret;
}
