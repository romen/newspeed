#ifndef _APPS_H
#define _APPS_H

#define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))

#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/evp.h>

extern BIO *bio_err;

void apps_init(void);
ENGINE *setup_engine(const char *engine, int debug);
void release_engine(ENGINE *e);

int EVP_PKEY_name_parser(int *nid, int *subparam, ENGINE **e, const char *name);

#define EVP_PKEY_keygen_wrapper(nid,subparam,engine) \
    _EVP_PKEY_keygen_wrapper((nid),(subparam),(engine),NULL)

EVP_PKEY *_EVP_PKEY_keygen_wrapper(const int type, int arg2, ENGINE *engine, EVP_PKEY_CTX **ret_kctx);

size_t EVP_PKEY_get1_PublicKey(const EVP_PKEY *pkey, unsigned char **ptr);

# define TM_START        0
# define TM_STOP         1
double app_tminterval(int stop, int usertime);

void* app_malloc(int sz, const char *what);

int app_isdir(const char *);

#include <unistd.h>
#define app_access(name, flag) access((name), (flag))

#endif /* _APPS_H */

/* vim: set ts=4 sw=4 tw=78 et : */
