#include "apps.h"

#include "ossl_compat.h"

#include <openssl/crypto.h>
#include <openssl/conf.h>

#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

#include <stdlib.h>
#include <string.h>

BIO *bio_err = NULL;

void apps_init(void)
{
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

#ifndef OPENSSL_V102_COMPAT
    OPENSSL_init_crypto(
            OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ENGINE_DYNAMIC,
            NULL);
#else
    if(!ERR_load_EXTRA_strings()) {
        fprintf(stderr, "ERR_load_EXTRA_strings failed\n");
        return;
    }

    OPENSSL_config(NULL);
#endif
}

#ifndef OPENSSL_NO_ENGINE
/* Try to load an engine in a shareable library */
static ENGINE *try_load_engine(const char *engine)
{
    ENGINE *e = ENGINE_by_id("dynamic");
    if (e) {
        if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
            || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
            ENGINE_free(e);
            e = NULL;
        }
    }
    return e;
}
#endif

ENGINE *setup_engine(const char *engine, int debug)
{
    ENGINE *e = NULL;

#ifndef OPENSSL_NO_ENGINE
    if (engine) {
        if (strcmp(engine, "auto") == 0) {
            BIO_printf(bio_err, "enabling auto ENGINE support\n");
            ENGINE_register_all_complete();
            return NULL;
        }
        if ((e = ENGINE_by_id(engine)) == NULL
            && (e = try_load_engine(engine)) == NULL) {
            BIO_printf(bio_err, "invalid engine \"%s\"\n", engine);
            ERR_print_errors(bio_err);
            return NULL;
        }
        if (debug) {
            ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM, 0, bio_err, 0);
        }
        //ENGINE_ctrl_cmd(e, "SET_USER_INTERFACE", 0, ui_method, 0, 1);
        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            BIO_printf(bio_err, "can't use that engine\n");
            ERR_print_errors(bio_err);
            ENGINE_free(e);
            return NULL;
        }

        BIO_printf(bio_err, "engine \"%s\" set.\n", ENGINE_get_id(e));
    }
#endif
    return e;
}

void release_engine(ENGINE *e)
{
#ifndef OPENSSL_NO_ENGINE
    if (e != NULL)
        /* Free our "structural" reference. */
        ENGINE_free(e);
#endif
}

EVP_PKEY *_EVP_PKEY_keygen_wrapper(const int type, int arg2,
                                         ENGINE *engine, EVP_PKEY_CTX **ret_kctx)
{
    int st = 0;
    // PARAMETER GENERATION ---------- {{{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;

    /* Create the context for generating the parameters */
    if (!(pctx = EVP_PKEY_CTX_new_id(type, engine))) {
        BIO_printf(bio_err,
                   "%s: Failure in parameters ctx generation\n",
                   OBJ_nid2sn(type));
        goto evp_keygen_err;
    }
    ERR_set_mark();
    if (!EVP_PKEY_paramgen_init(pctx)) {
        BIO_printf(bio_err, "%s: Failure in paramgen init\n", OBJ_nid2sn(type));
        goto evp_keygen_err;
    }
    ERR_pop_to_mark();

    /* Set the paramgen parameters according to the type */
    switch (type) {
    case EVP_PKEY_EC:
        /* Use arg2 as the NID for a named curve - defined in obj_mac.h */
        if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, arg2)) {
            BIO_printf(bio_err,
                       "%s: Failure in setting the curve nid: %d (%s)\n",
                       OBJ_nid2sn(type), arg2, OBJ_nid2sn(arg2));
            goto evp_keygen_err;
        }
        break;

    case EVP_PKEY_DSA:
        /* Set a bit length of arg2 bits */
        if (!EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx, arg2)) {
            BIO_printf(bio_err,
                       "%s: Failure in setting key bits: %d\n",
                       OBJ_nid2sn(type), arg2);
            goto evp_keygen_err;
        }
        break;

    case EVP_PKEY_DH:
        /* Set a bit length of arg2 bits */
        if (!EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, arg2)) {
            BIO_printf(bio_err,
                       "%s: Failure in setting key bits: %d\n",
                       OBJ_nid2sn(type), arg2);
            goto evp_keygen_err;
        }
        break;
    }

    /* Generate parameters */
    ERR_set_mark();
    st = EVP_PKEY_paramgen(pctx, &params);
    if (st != 1 && st != -2) {
        BIO_printf(bio_err,
                   "%s: Failure in params generation (returned %d)\n",
                   OBJ_nid2sn(type), st);
        goto evp_keygen_err;
    } else if (st == -2) {
        ERR_pop_to_mark();
    }
    // }}} ---------- PARAMETER GENERATION

    // {{{ KEY GENERATION ----------
    if (params != NULL) {
	if (type == EVP_PKEY_EC && !EVP_PKEY_set_alias_type(params, EVP_PKEY_EC))
            goto evp_keygen_err;
        kctx = EVP_PKEY_CTX_new(params, engine);
    } else {
        /* Create context for the key generation */
        kctx = EVP_PKEY_CTX_new_id(type, engine);
    }
    if (!kctx) {
        BIO_printf(bio_err,
                   "%s: Failure in keygen ctx generation\n", OBJ_nid2sn(type));
        goto evp_keygen_err;
    }

    if (!EVP_PKEY_keygen_init(kctx)) {
        BIO_printf(bio_err, "%s: Failure in keygen init\n", OBJ_nid2sn(type));
        goto evp_keygen_err;
    }

    /* RSA keys set the key length during key generation rather than parameter generation! */
    if (type == EVP_PKEY_RSA) {
        if (!EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, arg2)) {
            BIO_printf(bio_err,
                       "%s: Failure in setting key bits: %d\n",
                       OBJ_nid2sn(type), arg2);
            goto evp_keygen_err;
        }
    }

    /* Generate the key */
    if (!EVP_PKEY_keygen(kctx, &pkey)) {
        BIO_printf(bio_err,
                   "%s: Failure in key generation\n", OBJ_nid2sn(type));
        goto evp_keygen_err;
    }
    if (type == EVP_PKEY_EC && !EVP_PKEY_set_alias_type(pkey, EVP_PKEY_EC))
        goto evp_keygen_err;
    // }}} ---------- KEY GENERATION

    goto evp_keygen_end;
evp_keygen_err:
    ERR_print_errors(bio_err);
    pkey = NULL;
    if (ret_kctx != NULL)
        *ret_kctx = NULL;
    ret_kctx = NULL;
evp_keygen_end:
    if (ret_kctx != NULL && kctx != NULL) {
        *ret_kctx = kctx;
        kctx = NULL;
    }
    if (kctx)
        EVP_PKEY_CTX_free(kctx);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (params)
        EVP_PKEY_free(params);
    return pkey;
}



name_parser_st EVP_PKEY_name_parser(int *_nid, int *_subparam, ENGINE **_e, const char **fname, const char *name)
{
    name_parser_st rt = error;
    int nid = NID_undef;
    const char * arg2;
    int subparam = 0;
    ENGINE *e = NULL;

    size_t len = strlen(name);

    if (len > 12 && !strncmp(name, "EVP_PKEY_EC:", 12)) {
        nid = EVP_PKEY_EC;
        arg2 = &name[12];
        subparam = OBJ_sn2nid(arg2);
    } else if (len > 13 && !strncmp(name, "EVP_PKEY_DSA:", 13)) {
        nid = EVP_PKEY_DSA;
        //((char *)name)[12] = '\0';
        arg2 = &name[13];
        subparam = (int)strtol(arg2, NULL, 10);
    } else if (len > 13 && !strncmp(name, "EVP_PKEY_RSA:", 13)) {
        nid = EVP_PKEY_RSA;
        //((char *)name)[12] = '\0';
        arg2 = &name[13];
        subparam = (int)strtol(arg2, NULL, 10);
    } else if (fname != NULL && len > 15 && !strncmp(name, "PEM_PARAM_FILE:", 15)) {
        const char *p = &name[15];
        const char *_fname = NULL;

        if (len > 18 && !strncmp(p, "EC:", 3)) {
            _fname = &p[3];
            // FIXME: support more types of params (DH,DSA)
        } else {
            return error;
        }

        *fname = _fname;
        return ec_params_file;
    } else if (fname != NULL && len > 13 && !strncmp(name, "PEM_KEY_FILE:", 13)) {
        const char *_fname = &name[13];
        *fname = _fname;
        return key_file;
    } else {
        nid = OBJ_sn2nid(name);
        subparam = 0;

        if (nid == NID_undef) {
            BIO_printf(bio_err,
                    "%s is an unknown algorithm\n", name);
            goto end;
        }
        EVP_PKEY_asn1_find(&e, nid);
    }

    *_nid = nid;
    *_subparam = subparam;
    *_e = e;
    rt = success;
 end:
    return rt;
}

EC_GROUP *EC_GROUP_new_from_ecparams_fname(const char *fname)
{
    EC_GROUP *group = NULL;
    BIO *bio = NULL;

    if (NULL == (bio = BIO_new_file(fname, "r")))
        goto end;
    if (NULL == (group = PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL)))
        goto end;

 end:
    BIO_free(bio);
    return group;
}

EVP_PKEY *EVP_PKEY_new_from_ecparams_fname(const char *fname)
{
    EVP_PKEY *pkey = NULL, *ret = NULL;
    EC_KEY *eckey = NULL;
    EC_GROUP *group = NULL;

    if (NULL == (group = EC_GROUP_new_from_ecparams_fname(fname)))
        goto end;
    if (NULL == (eckey = EC_KEY_new())
            || NULL == (pkey = EVP_PKEY_new()))
        goto end;
    if (!EC_KEY_set_group(eckey, group))
        goto end;
    if (!EC_KEY_generate_key(eckey))
        goto end;
    if (!EVP_PKEY_set1_EC_KEY(pkey, eckey))
        goto end;

    ret = pkey;
    pkey = NULL;

 end:
    EVP_PKEY_free(pkey);
    EC_KEY_free(eckey);
    EC_GROUP_free(group);

    return ret;
}

EVP_PKEY *EVP_PKEY_new_private_from_fname(const char *fname)
{
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;

    if (NULL == (bio = BIO_new_file(fname, "r")))
        goto end;
    if (NULL == (pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)))
        goto end;

 end:
    BIO_free(bio);
    return pkey;
}


void* app_malloc(int sz, const char *what)
{
    void *vp = OPENSSL_malloc(sz);

    if (vp == NULL) {
        BIO_printf(bio_err, "Could not allocate %d bytes for %s\n",
                sz, what);
        ERR_print_errors(bio_err);
        exit(1);
    }
    return vp;
}

#if defined(_SC_CLK_TCK)      /* by means of unistd.h */
# include <sys/times.h>

double app_tminterval(int stop, int usertime)
{
    double ret = 0;
    struct tms rus;
    clock_t now = times(&rus);
    static clock_t tmstart;

    if (usertime)
        now = rus.tms_utime;

    if (stop == TM_START) {
        tmstart = now;
    } else {
        long int tck = sysconf(_SC_CLK_TCK);
        ret = (now - tmstart) / (double)tck;
    }

    return (ret);
}

#else
# include <sys/time.h>
# include <sys/resource.h>

double app_tminterval(int stop, int usertime)
{
    double ret = 0;
    struct rusage rus;
    struct timeval now;
    static struct timeval tmstart;

    if (usertime)
        getrusage(RUSAGE_SELF, &rus), now = rus.ru_utime;
    else
        gettimeofday(&now, NULL);

    if (stop == TM_START)
        tmstart = now;
    else
        ret = ((now.tv_sec + now.tv_usec * 1e-6)
               - (tmstart.tv_sec + tmstart.tv_usec * 1e-6));

    return ret;
}
#endif

/* app_isdir section */
# include <sys/stat.h>
# ifndef S_ISDIR
#  if defined(_S_IFMT) && defined(_S_IFDIR)
#   define S_ISDIR(a)   (((a) & _S_IFMT) == _S_IFDIR)
#  else
#   define S_ISDIR(a)   (((a) & S_IFMT) == S_IFDIR)
#  endif
# endif

int app_isdir(const char *name)
{
# if defined(S_ISDIR)
    struct stat st;

    if (stat(name, &st) == 0)
        return S_ISDIR(st.st_mode);
    else
        return -1;
# else
    return -1;
# endif
}

#include <openssl/pem.h>
size_t EVP_PKEY_get1_PublicKey(const EVP_PKEY *pkey, unsigned char **ptr)
{
    BIO *bio;
    BUF_MEM *bufferPtr;
    size_t ret;
    unsigned char *tmp;

    bio = BIO_new(BIO_s_mem());

    // int PEM_write_bio_PUBKEY(BIO *bp, EVP_PKEY *x);
    if (!PEM_write_bio_PUBKEY(bio, (EVP_PKEY*)pkey)) {
        return 0;
    }
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);
    //BIO_set_close(bio, BIO_NOCLOSE);

    if (bufferPtr == NULL) {
        ret = 0;
        goto end;
    }

    ret = bufferPtr->length;
    tmp = OPENSSL_memdup(bufferPtr->data, ret);

    if (tmp == NULL) {
        ret = 0;
        goto end;
    }

    *ptr = tmp;
end:
    BIO_free_all(bio);

    return ret;
}


/* vim: set ts=4 sw=4 tw=78 et : */
