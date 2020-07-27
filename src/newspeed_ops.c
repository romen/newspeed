#include "newspeed_config.h"
#include "newspeed_ops.h"
#include "newspeed_loop.h"
#include "apps.h"

#include <string.h> // memset

#define EVP_PKEY_KEYGEN_OP_DEFAULT_OUT_COUNT OP_DEFAULT_OUT_COUNT
#define EVP_PKEY_KEYGEN_OP_DEFAULT_IN_COUNT  OP_DEFAULT_IN_COUNT
#define EVP_PKEY_SIGN_OP_DEFAULT_OUT_COUNT OP_DEFAULT_OUT_COUNT
#define EVP_PKEY_SIGN_OP_DEFAULT_IN_COUNT  OP_DEFAULT_IN_COUNT
#define EVP_PKEY_VERIFY_OP_DEFAULT_OUT_COUNT OP_DEFAULT_OUT_COUNT
#define EVP_PKEY_VERIFY_OP_DEFAULT_IN_COUNT  OP_DEFAULT_IN_COUNT

#define EVP_PKEY_SIGNVRFY_INPUT_LEN 0x20

extern const char *prog; // newspeed.c

static const OP_METH op_meths[];

const OP_METH *OP_METH_find(OP_TYPE type)
{
    const OP_METH *op = op_meths;
    for(; op->type != OP_EOL && op->type != type; op++);
    if (type == op->type) return op;
    return NULL;
}

int OPERATION_malloc_results(OPERATION *op)
{
    int ret = 0;
    if (!op) goto end;
    uint64_t out_count = op->out_count, in_count = op->in_count;
    if (0 == out_count || 0 == in_count) goto end;

    uint64_t *times = op->times;
    if (NULL != times) {
        BIO_printf(bio_err, "FATAL: %s called, but previous buffer has not been freed.\n",
                __func__);
        goto end;
    }

    times = app_malloc(out_count*in_count*sizeof(*times), "results buffer");
    if(NULL == times) goto end;
    memset(times, 0, out_count*in_count*sizeof((times[0])));

    op->times = times;
    times = NULL; // so it is not freed
    ret = 1;
end:
    if (ret!= 1) {
        ERR_print_errors (bio_err);
    }

    if (times) {
        OPENSSL_free(times);
        times = NULL;
    }
    return ret;
}

int OPERATION_free_results(OPERATION *op)
{
    if (NULL == op || NULL == op->times) return 1;
    OPENSSL_free(op->times);
    op->times = NULL;
    return 1;
}

OPERATION *OPERATION_new(OP_TYPE type, const char *opt)
{
    OPERATION *op = NULL;
    const OP_METH *op_meth = OP_METH_find(type);
    if (NULL == op_meth) {
        BIO_printf(bio_err, "%s: operation (%d) not implemented\n", prog, type);
        return NULL;
    }

    if (NULL == (op=app_malloc(sizeof(*op), "OPERATION")))
        goto err;

    memset(op, 0, sizeof(*op));
    op->op_meth = op_meth;
    op->out_count = OP_DEFAULT_OUT_COUNT;
    op->in_count = OP_DEFAULT_IN_COUNT;
    if (NULL == op_meth->init || !op_meth->init(op, opt)) {
        BIO_printf(bio_err, "%s: Init failed for %s (\"%s\")\n",
                prog, op_meth->name, opt);
        goto err;
    }

    // allocate memory for the timing results
    if (!OPERATION_malloc_results(op)) {
        goto err;
    }

    return op;
err:
    if (op) OPENSSL_free(op);
    return NULL;
}

void OPERATION_free(OPERATION *op)
{
    if ( NULL == op )
        return;
    OPERATION_free_results(op);
    const OP_METH *op_meth = op->op_meth;
    if ( op_meth->cleanup ) {
        if (!op_meth->cleanup(op)) {
            BIO_printf(bio_err, "%s: cleanup failed for %s\n",
                    prog, op_meth->name);
        }
    }
    OPENSSL_free(op);
}

typedef struct op_evp_pkey_signvrfy_data_st {
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *signverify_ctx[ITERATIONS_PER_SAMPLE];
    EVP_PKEY_CTX *test_ctx;

    char *input;
    size_t inputlen;

    char *sigbuf;
    size_t sigbuf_len;
    size_t siglen;

} OP_EVP_PKEY_SIGNVRFY_DATA;

static int op_evp_pkey_signvrfy_setup(OPERATION *op)
{
    int ret = 0;
    OP_EVP_PKEY_SIGNVRFY_DATA *data = op->data;
    EVP_PKEY *pkey = data->pkey;
    EVP_PKEY_CTX *sign_ctx = data->signverify_ctx[0], *verify_ctx = data->test_ctx;
    char * sigbuf = NULL;
    size_t siglen = 0;

    /* Perform signature test */
    if (1 != EVP_PKEY_sign_init(sign_ctx)) {
        BIO_printf(bio_err, "EVP sign init failure.\n");
        goto end;
    }
    /* Determine siglen */
    if (1 != EVP_PKEY_sign(sign_ctx,
                NULL, &siglen,
                data->input, data->inputlen)) {
        BIO_printf(bio_err, "Failure determining signature length.\n");
        goto end;
    }
    if (NULL == (sigbuf = app_malloc(siglen*sizeof(*sigbuf), "signature buffer"))) {
        goto end;
    }
    data->sigbuf_len = siglen;

    // SIGN SOMETHING
    if (1 != EVP_PKEY_sign(sign_ctx,
                sigbuf,
                &siglen,
                data->input, data->inputlen)) {
        BIO_printf(bio_err, "EVP_PKEY_sign failure.\n");
        goto end;
    }

    /* Perform verification test */
    if (1 != EVP_PKEY_verify_init(verify_ctx)) {
        BIO_printf(bio_err, "EVP verify init failure.\n");
        goto end;
    }
    // VERIFY
    if(1 != (EVP_PKEY_verify(verify_ctx,
            sigbuf, siglen,
            data->input, data->inputlen) ) ) {
        BIO_printf(bio_err, "EVP_PKEY_verify failure.\n");
        goto end;
    }

    data->siglen = siglen;
    data->sigbuf = sigbuf; sigbuf = NULL;

    ret = 1;
end:

    if (ret != 1) {
        ERR_print_errors (bio_err);
        op->run = NULL;
    }

    if (sigbuf) {
        OPENSSL_free(sigbuf);
        sigbuf = NULL;
    }

    return ret;
}

static int op_evp_pkey_signvrfy_init(OPERATION *op, const char *arg)
{
    name_parser_st nps = error;
    int ret = 0;
    ENGINE *tmpengine = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *signverify_ctx[ITERATIONS_PER_SAMPLE] = {NULL};
    EVP_PKEY_CTX *test_ctx = NULL;
    int nid = NID_undef;
    int subparam = 0;
    char *input = NULL;
    size_t inputlen = EVP_PKEY_SIGNVRFY_INPUT_LEN;
    OP_EVP_PKEY_SIGNVRFY_DATA *data = NULL;
    const char *fname = NULL;

    nps = EVP_PKEY_name_parser(&nid, &subparam, &tmpengine, &fname, arg);
    if (nps == success) {
        pkey = EVP_PKEY_keygen_wrapper(nid, subparam, tmpengine);
        if (!pkey) {
            BIO_printf(bio_err, "%s: Cannot generate key for \"%s\"\n", prog, arg);
            goto end;
        }
    } else if (nps == ec_params_file) {
        if (NULL == (pkey = EVP_PKEY_new_from_ecparams_fname(fname)))
            goto end;
    } else if (nps == key_file) {
        if (NULL == (pkey = EVP_PKEY_new_private_from_fname(fname)))
            goto end;
    } else {
        goto end;
    }

    for (int i=0; i<ITERATIONS_PER_SAMPLE; i++) {
        // Derive signing/verifying context from key
        if (NULL == (signverify_ctx[i] = EVP_PKEY_CTX_new(pkey, tmpengine))) {
            BIO_printf(bio_err, "%s: EVP sign ctx generation failure for %s.\n",
                    prog, arg);
            goto end;
        }
    }

    // Derive context from key for testing
    if (NULL == (test_ctx = EVP_PKEY_CTX_new(pkey, tmpengine))) {
        BIO_printf(bio_err, "%s: EVP verify ctx generation failure for %s.\n",
                prog, arg);
        goto end;
    }

    if ( NULL == (input = app_malloc(inputlen*sizeof(*input), "input buffer"))) {
        goto end;
    }
    if (!RAND_bytes(input, inputlen)) {
        BIO_printf(bio_err, "%s: failure generating random input.\n", prog);
        goto end;
    }

    if ( NULL == (data = app_malloc(sizeof(*data), "OP_EVP_PKEY_SIGNVRFY_DATA"))) {
        goto end;
    }
    memset(data, 0, sizeof(*data));

    op->alg_name = arg;
    op->bits = EVP_PKEY_bits(pkey);
    op->nid = nid;

    data->pkey = pkey; pkey = NULL;

    memcpy(data->signverify_ctx, signverify_ctx, ITERATIONS_PER_SAMPLE*sizeof(*signverify_ctx));
    memset(signverify_ctx, 0, ITERATIONS_PER_SAMPLE*sizeof(*signverify_ctx));
    data->test_ctx = test_ctx; test_ctx = NULL;

    data->inputlen = inputlen;
    data->input = input; input = NULL;

    op->data = data; data = NULL;

    ret = 1;
end:
    if (ret!= 1) {
        ERR_print_errors (bio_err);
    }

    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    for (int i=0; i<ITERATIONS_PER_SAMPLE; i++) {
        if (signverify_ctx[i] != NULL) {
            EVP_PKEY_CTX_free(signverify_ctx[i]);
            signverify_ctx[i] = NULL;
        }
    }
    if (test_ctx != NULL) {
        EVP_PKEY_CTX_free(test_ctx);
        test_ctx = NULL;
    }

    if (tmpengine != NULL) {
        ENGINE_free(tmpengine);
        tmpengine = NULL;
    }

    if (input != NULL) {
        OPENSSL_free(input);
        input = NULL;
    }

    if (data != NULL) {
        OPENSSL_free(data);
        data = NULL;
    }

    return ret;
}

static int op_evp_pkey_sign_pre_run(void *arg)
{
    int ret = 0;
    OP_EVP_PKEY_SIGNVRFY_DATA *data = arg;
    EVP_PKEY_CTX **sctx = data->signverify_ctx;
    EVP_PKEY_CTX *test_ctx = data->test_ctx;
    size_t siglen = 0;

    if (NULL == data) goto end;

    // Initialize sign context
    for (int i=0; i<ITERATIONS_PER_SAMPLE; i++) {
        if (1 != EVP_PKEY_sign_init(sctx[i])) {
            BIO_printf(bio_err, "EVP sign init failure.\n");
            goto end;
        }
    }

    ret = 1;
end:
    if (ret!= 1) {
        ERR_print_errors (bio_err);
    }
    return ret;
}

static int op_evp_pkey_sign_run(int i, void *arg)
{
    OP_EVP_PKEY_SIGNVRFY_DATA *data = arg;
    size_t siglen = data->sigbuf_len;
    return EVP_PKEY_sign(data->signverify_ctx[i], data->sigbuf, &siglen, data->input, data->inputlen);
}

static int op_evp_pkey_sign_init(OPERATION *op, const char *arg)
{
    if(!op_evp_pkey_signvrfy_init(op, arg)) {
        return 0;
    }

    op->out_count = EVP_PKEY_SIGN_OP_DEFAULT_OUT_COUNT;
    op->in_count = EVP_PKEY_SIGN_OP_DEFAULT_IN_COUNT;

    op->setup = op_evp_pkey_signvrfy_setup;

    op->run = op_evp_pkey_sign_run;
    op->pre_run = op_evp_pkey_sign_pre_run;

    return 1;
}

static int op_evp_pkey_verify_pre_run(void *arg)
{
    OP_EVP_PKEY_SIGNVRFY_DATA *data = arg;

    if (NULL == data) return 0;

    for (int i=0; i<ITERATIONS_PER_SAMPLE; i++) {
        // Initialize verify context
        if (1 != EVP_PKEY_verify_init(data->signverify_ctx[i])) {
            BIO_printf(bio_err, "EVP verify init failure.\n");
            ERR_print_errors (bio_err);
            return 0;
        }
    }

    return 1;
}

static int op_evp_pkey_verify_run(int i, void *arg)
{
    OP_EVP_PKEY_SIGNVRFY_DATA *data = arg;
    return EVP_PKEY_verify(data->signverify_ctx[i], data->sigbuf, data->siglen, data->input, data->inputlen);
}

static int op_evp_pkey_verify_init(OPERATION *op, const char *arg)
{
    if(!op_evp_pkey_signvrfy_init(op, arg)) {
        return 0;
    }

    op->out_count = EVP_PKEY_VERIFY_OP_DEFAULT_OUT_COUNT;
    op->in_count = EVP_PKEY_VERIFY_OP_DEFAULT_IN_COUNT;

    op->setup = op_evp_pkey_signvrfy_setup;

    op->run = op_evp_pkey_verify_run;
    op->pre_run = op_evp_pkey_verify_pre_run;

    return 1;
}

static int op_evp_pkey_signvrfy_cleanup(OPERATION *op)
{
    if (op == NULL)
        return 0;

    if (op->data) {
        OP_EVP_PKEY_SIGNVRFY_DATA *data = op->data;

        if (data->pkey) {
            EVP_PKEY_free(data->pkey);
            data->pkey = NULL;
        }

        for (int i=0; i<ITERATIONS_PER_SAMPLE; i++) {
            if (data->signverify_ctx[i]) {
                EVP_PKEY_CTX_free(data->signverify_ctx[i]);
                data->signverify_ctx[i] = NULL;
            }
        }
        if (data->test_ctx) {
            EVP_PKEY_CTX_free(data->test_ctx);
            data->test_ctx = NULL;
        }

        if (data->input) {
            OPENSSL_free(data->input);
            data->input = NULL;
        }

        if (data->sigbuf) {
            OPENSSL_free(data->sigbuf);
            data->sigbuf = NULL;
        }

        OPENSSL_free(data);
        op->data = NULL;
    }

    return 1;
}


typedef struct op_evp_pkey_keygen_data_st {
    EVP_PKEY_CTX *kgen_ctx;
    EVP_PKEY *pkey;
} OP_EVP_PKEY_KEYGEN_DATA;

static int op_evp_pkey_keygen_setup(OPERATION *op)
{
    int ret = 0;
    OP_EVP_PKEY_KEYGEN_DATA *data = op->data;
    unsigned char *pubA = NULL, *pubB = NULL;
    size_t pubA_len = 0, pubB_len = 0;
    EVP_PKEY **ppkey = &(data->pkey);
    EVP_PKEY_CTX *kgen_ctx = data->kgen_ctx;

    /* Perform keygen test */
    if (!EVP_PKEY_keygen(kgen_ctx, ppkey)) {
        BIO_printf(bio_err,
                "%s: Failure during first key generation\n", op->alg_name);
        goto end;
    }
    if ( (pubA_len = EVP_PKEY_get1_PublicKey(*ppkey, &pubA)) == 0 ) {
        BIO_printf(bio_err,
                "%s: Failure extracting first public key\n", op->alg_name);
        goto end;
    }

    if (!EVP_PKEY_keygen(kgen_ctx, ppkey)) {
        BIO_printf(bio_err,
                "%s: Failure during second key generation\n", op->alg_name);
        goto end;
    }
    if ( (pubB_len = EVP_PKEY_get1_PublicKey(*ppkey, &pubB)) == 0 ) {
        BIO_printf(bio_err,
                "%s: Failure extracting second public key\n", op->alg_name);
        goto end;
    }

    /* The two generated keys should be different */
    if (pubA_len == pubB_len && (0 == memcmp(pubA, pubB, pubA_len)) ) {
        // the public keys are identical: wrong!
        BIO_printf(bio_err,
                "%s: randomly generated keys must differ\n", op->alg_name);
        goto end;
    }

    ret = 1;
end:
    if (ret!= 1) {
        ERR_print_errors (bio_err);
    }

    if (pubA) {
        free(pubA);
        pubA = NULL;
    }
    if (pubB) {
        free(pubB);
        pubB = NULL;
    }

    if (ret != 1) {
        op->run = NULL;
    }

    return ret;
}

static int op_evp_pkey_keygen_run(int i, void *arg)
{
    OP_EVP_PKEY_KEYGEN_DATA *data = arg;
    return EVP_PKEY_keygen(data->kgen_ctx, &(data->pkey));
}

static int op_evp_pkey_keygen_init(OPERATION *op, const char *arg)
{
    int ret = 0;
    ENGINE *tmpengine = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *kgen_ctx = NULL;
    int nid = NID_undef;
    int subparam = 0;
    OP_EVP_PKEY_KEYGEN_DATA *data = NULL;
    name_parser_st nps = error;
    const char *fname = NULL;

    nps = EVP_PKEY_name_parser(&nid, &subparam, &tmpengine, &fname, arg);
    if (nps == success) {
        pkey = _EVP_PKEY_keygen_wrapper(nid, subparam, tmpengine, &kgen_ctx);
        if (!pkey || !kgen_ctx) {
            BIO_printf(bio_err, "%s: Cannot generate keygen context for \"%s\"\n", prog, arg);
            goto end;
        }
    } else if (nps == ec_params_file || nps == key_file) {
        if (nps == key_file) {
            pkey = EVP_PKEY_new_private_from_fname(fname);
        } else {
            pkey = EVP_PKEY_new_from_ecparams_fname(fname);
        }
        if (NULL == pkey)
            goto end;

        if (NULL == (kgen_ctx = EVP_PKEY_CTX_new(pkey, NULL))) {
            BIO_printf(bio_err, "%s: Failure in keygen ctx generation\n", fname);
            goto end;
        }

        if (!EVP_PKEY_keygen_init(kgen_ctx)) {
            BIO_printf(bio_err, "%s: Failure in keygen init\n", fname);
            goto end;
        }
        
        /* free the key read from the file system */
        EVP_PKEY_free(pkey);
        pkey = NULL;

        /*
         * generate a new key using the same parameters to ensure
         * kgen_ctx can be used
         */
        if (!EVP_PKEY_keygen(kgen_ctx, &pkey)) {
            BIO_printf(bio_err, "%s: Failure in key generation\n", fname);
            goto end;
        }
    } else {
        goto end;
    }


    if ( NULL == (data = app_malloc(sizeof(*data), "OP_EVP_PKEY_KEYGEN_DATA"))) {
        goto end;
    }
    memset(data, 0, sizeof(*data));
    data->kgen_ctx = kgen_ctx;
    kgen_ctx = NULL;

    op->data = data;
    op->alg_name = arg;
    op->out_count = EVP_PKEY_KEYGEN_OP_DEFAULT_OUT_COUNT;
    op->in_count = EVP_PKEY_KEYGEN_OP_DEFAULT_IN_COUNT;
    op->bits = EVP_PKEY_bits(pkey);
    op->nid = nid;

    op->setup = op_evp_pkey_keygen_setup;
    op->run = op_evp_pkey_keygen_run;

    ret = 1;
end:

    if (ret!= 1) {
        ERR_print_errors (bio_err);
    }

    if (kgen_ctx != NULL) {
        EVP_PKEY_CTX_free(kgen_ctx);
        kgen_ctx = NULL;
    }

    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    if (tmpengine != NULL) {
        ENGINE_free(tmpengine);
        tmpengine = NULL;
    }

    if (ret!=1 && data) {
        OPENSSL_free(data);
        data = NULL;
    }

    return ret;
}

static int op_evp_pkey_keygen_cleanup(OPERATION *op)
{
    if (op == NULL)
        return 0;

    if (op->data) {
        OP_EVP_PKEY_KEYGEN_DATA *data = op->data;

        if (data->pkey) {
            EVP_PKEY_free(data->pkey);
            data->pkey = NULL;
        }

        if (data->kgen_ctx) {
            EVP_PKEY_CTX_free(data->kgen_ctx);
            data->kgen_ctx = NULL;
        }

        OPENSSL_free(data);
        op->data = NULL;
    }

    return 1;
}

#define OP_EVP_PKEY_DERIVE_DATA_KEYS 10
#define OP_EVP_PKEY_DERIVE_DATA_PEERKEYS 10
typedef struct op_evp_pkey_derive_data_st {
    EVP_PKEY *peerkey[OP_EVP_PKEY_DERIVE_DATA_KEYS];
    EVP_PKEY_CTX *dctx[ITERATIONS_PER_SAMPLE]; // derivation ctx

    EVP_PKEY *pkey; // associated with dctx[0], used for testing during _setup()
    ENGINE *engine; // used for deriving a EVP_PKEY_CTX for testing during _setup()

    char *shared_secret;
    size_t buflen;
} OP_EVP_PKEY_DERIVE_DATA;

static int op_evp_pkey_derive_setup(OPERATION *op)
{
    int ret = 0;
    size_t buflen = 0, buflen2 = 0;
    char *testbuffer = NULL;
    EVP_PKEY_CTX *testctx = NULL;
    if (!op || op->data == NULL) return 0;
    OP_EVP_PKEY_DERIVE_DATA *data = op->data;

    // data->dctx[0] is associated with data->pkey
    if (!EVP_PKEY_derive_init(data->dctx[0])) {
        BIO_printf(bio_err, "EVP_PKEY_derive_init() failed\n");
        goto end;
    }

    if (!EVP_PKEY_derive_set_peer(data->dctx[0], data->peerkey[0])) {
        BIO_printf(bio_err, "EVP_PKEY_derive_set_peer() failed\n");
        goto end;
    }
    EVP_PKEY_CTX_ctrl_str(data->dctx[0], "ukmhex", "0100000000000000");

    if (!EVP_PKEY_derive(data->dctx[0], NULL, &buflen)) {
        BIO_printf(bio_err, "Failed to determine shared secret length\n");
        goto end;
    }

    if (buflen == 0 ) {
        BIO_printf(bio_err, "invalid shared secret length\n");
        goto end;
    }

    if (NULL == (data->shared_secret = app_malloc(
                    buflen*sizeof(*(data->shared_secret)),
                    "shared secret buffer"))) {
        goto end;
    }
    data->buflen = buflen;

    if (!EVP_PKEY_derive(data->dctx[0], data->shared_secret, &buflen)) {
        BIO_printf(bio_err, "EVP_PKEY_derive() failed\n");
        goto end;
    }

    /* Test by simmetrically running key derivation on the peerkey and
     * comparing the derived secrets for equality */

    if (NULL == (testctx = EVP_PKEY_CTX_new(data->peerkey[0], data->engine)) ) {
        BIO_printf(bio_err, "failed to create a key derivation ctx for testing\n");
        goto end;
    }

    if (!EVP_PKEY_derive_init(testctx)) {
        BIO_printf(bio_err, "failed to initialize key derivation ctx for testing\n");
        goto end;
    }

    if (!EVP_PKEY_derive_set_peer(testctx, data->pkey)) {
        BIO_printf(bio_err, "failed to derivation set peer key for testing\n");
        goto end;
    }

    ERR_set_mark();
    EVP_PKEY_CTX_ctrl_str(testctx, "ukmhex", "0100000000000000");
    ERR_pop_to_mark();

    if (!EVP_PKEY_derive(testctx, NULL, &buflen2)) {
        BIO_printf(bio_err, "unable to determine shared secret length\n");
        goto end;
    }

    if (buflen != buflen2) {
        BIO_printf(bio_err, "shared secret length mismatch\n");
        goto end;
    }

    if (NULL == (testbuffer = app_malloc(buflen2*sizeof(*testbuffer), "temporary buffer"))) {
        goto end;
    }

    if (!EVP_PKEY_derive(testctx, testbuffer, &buflen2) || buflen != buflen2) {
        BIO_printf(bio_err, "EVP_PKEY_derive() failed\n");
        goto end;
    }

    if (0 != CRYPTO_memcmp(testbuffer, data->shared_secret, buflen)) {
        BIO_printf(bio_err, "Derive shared secrets do not match\n");
        goto end;
    }

    ret = 1;
end:
    if (ret != 1) {
        ERR_print_errors (bio_err);
        op->run = NULL;
    }

    if (testbuffer) {
        OPENSSL_free(testbuffer);
        testbuffer = NULL;
    }

    if (testctx) {
        EVP_PKEY_CTX_free(testctx);
        testctx = NULL;
    }

    return ret;
}

static int op_evp_pkey_derive_pre_run(void *arg)
{
    int ret = 0;
    size_t buflen = 0;
    if (arg == NULL)
        return 0;

    OP_EVP_PKEY_DERIVE_DATA *data = arg;

    for (int i=0; i<ITERATIONS_PER_SAMPLE; i++) {
        if (!EVP_PKEY_derive_init(data->dctx[i])) {
            BIO_printf(bio_err, "EVP_PKEY_derive_init() failed\n");
            goto end;
        }

        if (!EVP_PKEY_derive_set_peer(data->dctx[i], data->peerkey[i%OP_EVP_PKEY_DERIVE_DATA_PEERKEYS])) {
            BIO_printf(bio_err, "EVP_PKEY_derive_set_peer() failed\n");
            goto end;
        }
    }

    ret = 1;
end:
    if (ret != 1) {
        ERR_print_errors (bio_err);
    }

    return ret;
}

static int op_evp_pkey_derive_run(int i, void *arg)
{
    OP_EVP_PKEY_DERIVE_DATA *data = arg;
    EVP_PKEY_CTX_ctrl_str(data->dctx[i], "ukmhex", "0100000000000000");
    return EVP_PKEY_derive(data->dctx[i], data->shared_secret, &(data->buflen));
}

static int op_evp_pkey_derive_cleanup(OPERATION *op)
{
    if (op == NULL || NULL == op->data)
        return 0;

    OP_EVP_PKEY_DERIVE_DATA *data = op->data;

    for (int i=0; i<OP_EVP_PKEY_DERIVE_DATA_PEERKEYS; i++) {
        if (data->peerkey[i]) {
            EVP_PKEY_free(data->peerkey[i]);
            data->peerkey[i] = NULL;
        }
    }

    for (int i=0; i<ITERATIONS_PER_SAMPLE; i++) {
        if (data->dctx[i]) {
            EVP_PKEY_CTX_free(data->dctx[i]);
            data->dctx[i] = NULL;
        }
    }

    if (data->pkey) {
        EVP_PKEY_free(data->pkey);
        data->pkey = NULL;
    }

    if (data->engine) {
        ENGINE_free(data->engine);
        data->engine = NULL;
    }

    if (data->shared_secret) {
        OPENSSL_free(data->shared_secret);
        data->shared_secret = NULL;
    }

    OPENSSL_free(data);
    op->data = NULL;

    return 1;
}


static int op_evp_pkey_derive_init(OPERATION *op, const char *arg)
{
    int ret = 0;
    ENGINE *tmpengine = NULL;
    EVP_PKEY *pkey[OP_EVP_PKEY_DERIVE_DATA_KEYS] = {NULL};
    EVP_PKEY *peerkey[OP_EVP_PKEY_DERIVE_DATA_PEERKEYS] = {NULL};
    EVP_PKEY_CTX *kgen_ctx = NULL, *dctx[ITERATIONS_PER_SAMPLE] = {NULL};
    int nid = NID_undef;
    int subparam = 0;
    OP_EVP_PKEY_DERIVE_DATA *data = NULL;
    const char *fname = NULL;
    name_parser_st nps = error;

   nps = EVP_PKEY_name_parser(&nid, &subparam, &tmpengine, &fname, arg);
    if (nps == success) {
        pkey[0] = _EVP_PKEY_keygen_wrapper(nid, subparam, tmpengine, &kgen_ctx);
        if (!pkey[0] || !kgen_ctx) {
            BIO_printf(bio_err, "%s: Cannot generate keygen context for \"%s\"\n", prog, arg);
            goto end;
        }
    } else if (nps == ec_params_file || nps == key_file) {
        if (nps == key_file) {
            pkey[0] = EVP_PKEY_new_private_from_fname(fname);
        } else {
            pkey[0] = EVP_PKEY_new_from_ecparams_fname(fname);
        }
        if (NULL == pkey[0])
            goto end;

        if (NULL == (kgen_ctx = EVP_PKEY_CTX_new(pkey[0], NULL))) {
            BIO_printf(bio_err, "%s: Failure in keygen ctx generation\n", fname);
            goto end;
        }

        if (!EVP_PKEY_keygen_init(kgen_ctx)) {
            BIO_printf(bio_err, "%s: Failure in keygen init\n", fname);
            goto end;
        }
        
        /* free the key read from the file system */
        EVP_PKEY_free(pkey[0]);
        pkey[0] = NULL;

        /*
         * generate a new key using the same parameters to ensure
         * kgen_ctx can be used
         */
        if (!EVP_PKEY_keygen(kgen_ctx, &pkey[0])) {
            BIO_printf(bio_err, "%s: Failure in key generation\n", fname);
            goto end;
        }
    } else {
        goto end;
    }

 
    for(int i=1; i<OP_EVP_PKEY_DERIVE_DATA_KEYS; i++) {
        if (!EVP_PKEY_keygen(kgen_ctx, &(pkey[i]))) {
            BIO_printf(bio_err, "Key generation failed\n");
            goto end;
        }
        if (strncmp("EVP_PKEY_EC:SM2", arg, 15) == 0
            && !EVP_PKEY_set_alias_type(pkey[i], EVP_PKEY_EC))
            goto end;
    }
    for(int i=0; i<OP_EVP_PKEY_DERIVE_DATA_PEERKEYS; i++) {
        if (!EVP_PKEY_keygen(kgen_ctx, &(peerkey[i]))) {
            BIO_printf(bio_err, "Peer key generation failed\n");
            goto end;
        }
        if (strncmp("EVP_PKEY_EC:SM2", arg, 15) == 0
            && !EVP_PKEY_set_alias_type(peerkey[i], EVP_PKEY_EC))
            goto end;
    }

    for (int i=0; i<ITERATIONS_PER_SAMPLE; i++) {
        if (NULL == (dctx[i] = EVP_PKEY_CTX_new(pkey[i % OP_EVP_PKEY_DERIVE_DATA_KEYS], tmpengine))) {
            BIO_printf(bio_err, "%s: Cannot generate derivation context for \"%s\"\n", prog, arg);
            goto end;
        }
        ERR_set_mark();
        EVP_PKEY_CTX_ctrl_str(dctx[i], "ukmhex", "0100000000000000");
        ERR_pop_to_mark();
    }

    if ( NULL == (data = app_malloc(sizeof(*data), "OP_EVP_PKEY_DERIVE_DATA"))) {
        goto end;
    }
    memset(data, 0, sizeof(*data));

    op->alg_name = arg;
    op->out_count = EVP_PKEY_KEYGEN_OP_DEFAULT_OUT_COUNT;
    op->in_count = EVP_PKEY_KEYGEN_OP_DEFAULT_IN_COUNT;
    op->bits = EVP_PKEY_bits(pkey[0]);
    op->nid = nid;

    data->pkey = pkey[0]; pkey[0] = NULL;
    memcpy(data->peerkey, peerkey, OP_EVP_PKEY_DERIVE_DATA_PEERKEYS*sizeof(peerkey[0]));
    memset(peerkey, 0, OP_EVP_PKEY_DERIVE_DATA_PEERKEYS*sizeof(peerkey[0]));
    memcpy(data->dctx, dctx, ITERATIONS_PER_SAMPLE*sizeof(dctx[0]));
    memset(dctx, 0, ITERATIONS_PER_SAMPLE*sizeof(dctx[0]));
    data->engine = tmpengine; tmpengine = NULL;

    op->data = data; data = NULL;

    op->setup = op_evp_pkey_derive_setup;
    op->run = op_evp_pkey_derive_run;
    op->pre_run = op_evp_pkey_derive_pre_run;

    ret = 1;
end:
    if (ret!= 1) {
        ERR_print_errors (bio_err);
    }

    for (int i=0; i<OP_EVP_PKEY_DERIVE_DATA_KEYS; i++) {
        if (pkey[i] != NULL) {
            EVP_PKEY_free(pkey[i]);
            pkey[i] = NULL;
        }
    }
    for (int i=0; i<OP_EVP_PKEY_DERIVE_DATA_PEERKEYS; i++) {
        if (peerkey[i] != NULL) {
            EVP_PKEY_free(peerkey[i]);
            peerkey[i] = NULL;
        }
    }

    if (kgen_ctx) {
        EVP_PKEY_CTX_free(kgen_ctx);
        kgen_ctx = NULL;
    }

    for (int i=0; i<ITERATIONS_PER_SAMPLE; i++) {
        if (dctx[i]) {
            EVP_PKEY_CTX_free(dctx[i]);
            dctx[i] = NULL;
        }
    }

    if (tmpengine != NULL) {
        ENGINE_free(tmpengine);
        tmpengine = NULL;
    }

    if (data) {
        OPENSSL_free(data);
        data = NULL;
    }

    return ret;
}


#ifdef ENABLE_OP_EVP_DIGESTSIGN
typedef struct op_evp_digestsignvrfy_data_st {
    EVP_PKEY *pkey;
    EVP_MD_CTX *mdctx[ITERATIONS_PER_SAMPLE];
    EVP_MD *mdtype;
    ENGINE *engine;

    char *input;
    size_t inputlen;

    char *sigbuf;
    size_t sigbuf_len;
    size_t siglen;

} OP_EVP_DIGESTSIGNVRFY_DATA;

static int op_evp_digestsignvrfy_setup(OPERATION *op)
{
    int ret = 0;
    OP_EVP_DIGESTSIGNVRFY_DATA *data = op->data;
    EVP_PKEY *pkey = data->pkey;
    EVP_MD *mdtype = data->mdtype;
    EVP_MD_CTX *mdctx = data->mdctx[0];
    ENGINE *engine = data->engine;
    char *sigbuf = NULL;
    size_t siglen = 0;

    /* Perform signature test */
    if (!EVP_MD_CTX_reset(mdctx)) {
        BIO_printf(bio_err, "EVP_MD_CTX_reset() failed\n");
        return 0;
    }
    EVP_MD_CTX_set_flags(mdctx, EVP_MD_CTX_FLAG_FINALISE);

    if (1 != EVP_DigestSignInit(mdctx, NULL, mdtype, engine, pkey)) {
        BIO_printf(bio_err, "EVP sign init failure.\n");
        goto end;
    }
    /* Determine siglen */
    if (1 != EVP_DigestSign(mdctx,
                NULL, &siglen,
                data->input, data->inputlen)) {
        BIO_printf(bio_err, "Failure determining signature length.\n");
        goto end;
    }
    if (NULL == (sigbuf = app_malloc(siglen*sizeof(*sigbuf), "signature buffer"))) {
        goto end;
    }
    data->sigbuf_len = siglen;

    // SIGN SOMETHING
    if (1 != EVP_DigestSign(mdctx,
                sigbuf, &siglen,
                data->input, data->inputlen)) {
        BIO_printf(bio_err, "EVP_DigestSign failure.\n");
        goto end;
    }

    /* Perform verification test */
    if (!EVP_MD_CTX_reset(mdctx)) {
        BIO_printf(bio_err, "EVP_MD_CTX_reset() failed\n");
        return 0;
    }
    EVP_MD_CTX_set_flags(mdctx, EVP_MD_CTX_FLAG_FINALISE);

    if (1 != EVP_DigestVerifyInit(mdctx, NULL, mdtype, engine, pkey)) {
        BIO_printf(bio_err, "EVP verify init failure.\n");
        goto end;
    }
    // VERIFY
    if(1 != (EVP_DigestVerify(mdctx,
            sigbuf, siglen,
            data->input, data->inputlen) ) ) {
        BIO_printf(bio_err, "EVP_DigestVerify failure.\n");
        goto end;
    }

    data->sigbuf = sigbuf; sigbuf = NULL;
    data->siglen = siglen;

    ret = 1;
end:

    if (ret != 1) {
        ERR_print_errors (bio_err);
        op->run = NULL;
    }

    if (sigbuf) {
        OPENSSL_free(sigbuf);
        sigbuf = NULL;
    }

    return ret;
}

static int op_evp_digestsignvrfy_init(OPERATION *op, const char *arg)
{
    int ret = 0;
    ENGINE *tmpengine = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD *mdtype = NULL;
    EVP_MD_CTX *mdctx[ITERATIONS_PER_SAMPLE] = {NULL};
    int nid = NID_undef;
    int subparam = 0;
    char *input = NULL;
    size_t inputlen = EVP_PKEY_SIGNVRFY_INPUT_LEN;
    OP_EVP_DIGESTSIGNVRFY_DATA *data = NULL;
    const char *fname = NULL;
    name_parser_st nps = error;

    nps = EVP_PKEY_name_parser(&nid, &subparam, &tmpengine, &fname, arg);
    if (nps == success) {
        pkey = EVP_PKEY_keygen_wrapper(nid, subparam, tmpengine);
        if (!pkey) {
            BIO_printf(bio_err, "%s: Cannot generate key for \"%s\"\n", prog, arg);
            goto end;
        }
    } else if (nps == ec_params_file) {
        if (NULL == (pkey = EVP_PKEY_new_from_ecparams_fname(fname)))
            goto end;
    } else if (nps == key_file) {
        if (NULL == (pkey = EVP_PKEY_new_private_from_fname(fname)))
            goto end;
    } else {
        goto end;
    }

    for (int i=0; i<ITERATIONS_PER_SAMPLE; i++) {
        if ( NULL == (mdctx[i] = EVP_MD_CTX_new()) ) {
            BIO_printf(bio_err, "%s: EVP_MD_CTX_new() failed.\n", prog);
            goto end;
        }
    }

    if ( NULL == (input = app_malloc(inputlen*sizeof(*input), "input buffer"))) {
        goto end;
    }
    if (!RAND_bytes(input, inputlen)) {
        BIO_printf(bio_err, "%s: failure generating random input.\n", prog);
        goto end;
    }

    if ( NULL == (data = app_malloc(sizeof(*data), "OP_EVP_DIGESTSIGNVRFY_DATA"))) {
        goto end;
    }
    memset(data, 0, sizeof(*data));

    op->alg_name = arg;
    op->bits = EVP_PKEY_bits(pkey);
    op->nid = nid;

    data->pkey = pkey; pkey = NULL;
    data->inputlen = inputlen;
    data->input = input; input = NULL;

    memcpy(data->mdctx, mdctx, ITERATIONS_PER_SAMPLE*sizeof(*mdctx));
    memset(mdctx, 0, ITERATIONS_PER_SAMPLE*sizeof(*mdctx));

    data->mdtype = mdtype; mdtype = NULL;
    data->engine = tmpengine; tmpengine = NULL;

    op->data = data; data = NULL;

    ret = 1;
end:
    if (ret!= 1) {
        ERR_print_errors (bio_err);
    }

    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    if (tmpengine != NULL) {
        ENGINE_free(tmpengine);
        tmpengine = NULL;
    }

    if (input != NULL) {
        OPENSSL_free(input);
        input = NULL;
    }

    for(int i=0; i<ITERATIONS_PER_SAMPLE; i++) {
        if (mdctx[i] != NULL) {
            EVP_MD_CTX_free(mdctx[i]);
            mdctx[i] = NULL;
        }
    }

    if (mdtype != NULL) {
        mdtype = NULL;
    }


    if (data != NULL) {
        OPENSSL_free(data);
        data = NULL;
    }

    return ret;
}

static int op_evp_digestsign_pre_run(void *arg)
{
    int ret = 0;
    OP_EVP_DIGESTSIGNVRFY_DATA *data = arg;

    // Initialize sign context
    for (int i=0; i<ITERATIONS_PER_SAMPLE; i++) {
        if (!EVP_MD_CTX_reset(data->mdctx[i])) {
            BIO_printf(bio_err, "EVP_MD_CTX_reset() failed\n");
            goto end;
        }
        EVP_MD_CTX_set_flags(data->mdctx[i], EVP_MD_CTX_FLAG_FINALISE);

        if (!EVP_DigestSignInit(data->mdctx[i], NULL, data->mdtype, data->engine, data->pkey)) {
            BIO_printf(bio_err, "EVP_DigestSignInit() failed\n");
            goto end;
        }
    }

    ret = 1;
end:
    if (ret != 1) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "Signature generation requires a bigger buffer.\n");
        goto end;
    }

    return ret;
}

static int op_evp_digestsign_run(int i, void *arg)
{
    OP_EVP_DIGESTSIGNVRFY_DATA *data = arg;
    size_t siglen = data->sigbuf_len;

    return EVP_DigestSign(data->mdctx[i], data->sigbuf, &siglen, data->input, data->inputlen);
}


static int op_evp_digestsign_init(OPERATION *op, const char *arg)
{
    if(!op_evp_digestsignvrfy_init(op, arg)) {
        return 0;
    }

    op->out_count = EVP_PKEY_SIGN_OP_DEFAULT_OUT_COUNT;
    op->in_count = EVP_PKEY_SIGN_OP_DEFAULT_IN_COUNT;

    op->setup = op_evp_digestsignvrfy_setup;

    op->pre_run = op_evp_digestsign_pre_run;
    op->run = op_evp_digestsign_run;

    return 1;
}

static int op_evp_digestverify_pre_run(void *arg)
{
    int ret = 0;
    OP_EVP_DIGESTSIGNVRFY_DATA *data = arg;

    for (int i=0; i<ITERATIONS_PER_SAMPLE; i++) {
        if (!EVP_MD_CTX_reset(data->mdctx[i])) {
            BIO_printf(bio_err, "EVP_MD_CTX_reset() failed\n");
            goto end;
        }
        EVP_MD_CTX_set_flags(data->mdctx[i], EVP_MD_CTX_FLAG_FINALISE);

        if (!EVP_DigestVerifyInit(data->mdctx[i], NULL, data->mdtype, data->engine, data->pkey)) {
            BIO_printf(bio_err, "EVP_DigestVerifyInit() failed\n");
            goto end;
        }
    }

    ret = 1;
end:
    if (ret != 1) {
        ERR_print_errors(bio_err);
    }

    return ret;
}

static int op_evp_digestverify_run(int i, void *arg)
{
    OP_EVP_DIGESTSIGNVRFY_DATA *data = arg;

    return EVP_DigestVerify(data->mdctx[i], data->sigbuf, data->siglen, data->input, data->inputlen);
}

static int op_evp_digestverify_init(OPERATION *op, const char *arg)
{
    if(!op_evp_digestsignvrfy_init(op, arg)) {
        return 0;
    }

    op->out_count = EVP_PKEY_VERIFY_OP_DEFAULT_OUT_COUNT;
    op->in_count = EVP_PKEY_VERIFY_OP_DEFAULT_IN_COUNT;

    op->setup = op_evp_digestsignvrfy_setup;

    op->run = op_evp_digestverify_run;
    op->pre_run = op_evp_digestverify_pre_run;

    return 1;
}

static int op_evp_digestsignvrfy_cleanup(OPERATION *op)
{
    if (op == NULL)
        return 0;

    if (op->data) {
        OP_EVP_DIGESTSIGNVRFY_DATA *data = op->data;

        if (data->pkey) {
            EVP_PKEY_free(data->pkey);
            data->pkey = NULL;
        }

        if (data->input) {
            OPENSSL_free(data->input);
            data->input = NULL;
        }

        if (data->sigbuf) {
            OPENSSL_free(data->sigbuf);
            data->sigbuf = NULL;
        }

        for (int i=0; i<ITERATIONS_PER_SAMPLE; i++) {
            if (data->mdctx[i] != NULL) {
                EVP_MD_CTX_free(data->mdctx[i]);
                data->mdctx[i] = NULL;
            }
        }

        if (data->mdtype != NULL) {
            data->mdtype = NULL;
        }

        if (data->engine != NULL) {
            ENGINE_free(data->engine);
            data->engine = NULL;
        }

        OPENSSL_free(data);
        op->data = NULL;
    }

    return 1;
}
#endif /* ENABLE_OP_EVP_DIGESTSIGN */


////////////////////////////////////////// NOOP
static int op_noop_setup(OPERATION *op)
{
    return 1;
}

static int op_noop_run(int i, void *arg)
{
    *(int*)arg = NID_undef;
    return 1;
}

static int op_noop_init(OPERATION *op, const char *arg)
{
    int ret = 0;

    op->data = &(op->nid);
    op->alg_name = arg;
    op->out_count = OP_DEFAULT_OUT_COUNT;
    op->in_count = OP_DEFAULT_IN_COUNT;
    op->bits = 0;
    op->nid = NID_undef;

    op->setup = op_noop_setup;
    op->run = op_noop_run;

    ret = 1;
    return ret;
}

static const OP_METH op_meths[] = {
    { OP_NOOP, "NOOP", op_noop_init, NULL },
    { OP_EVP_PKEY_KEYGEN, "evp_pkey_keygen", op_evp_pkey_keygen_init, op_evp_pkey_keygen_cleanup},
    { OP_EVP_PKEY_DERIVE, "evp_pkey_derive", op_evp_pkey_derive_init, op_evp_pkey_derive_cleanup},
    { OP_EVP_PKEY_SIGN, "evp_pkey_sign", op_evp_pkey_sign_init, op_evp_pkey_signvrfy_cleanup},
    { OP_EVP_PKEY_VERIFY, "evp_pkey_verify", op_evp_pkey_verify_init, op_evp_pkey_signvrfy_cleanup},
#ifdef ENABLE_OP_EVP_DIGESTSIGN
    { OP_EVP_DIGESTSIGN, "evp_digestsign", op_evp_digestsign_init, op_evp_digestsignvrfy_cleanup},
    { OP_EVP_DIGESTVERIFY, "evp_digestverify", op_evp_digestverify_init, op_evp_digestsignvrfy_cleanup},
#endif /* ENABLE_OP_EVP_DIGESTSIGN */
    { OP_EOL } // ends the list
};


/* vim: set ts=4 sw=4 tw=78 et : */
