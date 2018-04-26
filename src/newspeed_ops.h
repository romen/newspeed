#ifndef _HEADER_NEWSPEED_OPS_H
#define _HEADER_NEWSPEED_OPS_H

#include <openssl/engine.h>
#include <inttypes.h>

typedef enum OP_type {
    OP_NOOP = 0,
    OP_EVP_PKEY_KEYGEN = 1,
    OP_EVP_PKEY_DERIVE,
    OP_EVP_PKEY_SIGN, OP_EVP_PKEY_VERIFY,
    OP_EVP_DIGESTSIGN, OP_EVP_DIGESTVERIFY,
    OP_EOL = -1
} OP_TYPE;

typedef struct op_meth_st OP_METH;
typedef struct operation_st OPERATION;
typedef struct OP_stats_st {
    char guard;
    uint64_t spurious, tot_var, abs_max_dev, var_var;
    uint64_t min_min, var_min;
    uint64_t median;
    double avg, std, rel_std;
} OP_STATS;

typedef struct operation_st {
    void *data;
    int (*setup)(OPERATION *op);
    int (*pre_run)(void *arg);
    int (*run)(int iteration, void *arg);
    int (*post_run)(void *arg);
    const OP_METH *op_meth;
    const char *alg_name;
    int bits;
    int nid;

    int quiet;

    int out_count;
    int in_count;
    uint64_t *times;
    OP_STATS stats;

    int success;
} OPERATION;

typedef struct op_meth_st {
    const OP_TYPE type;
    const char *name;
    int (*init)(OPERATION *, const char *arg);
    int (*cleanup)(OPERATION *);
} OP_METH;

#define OPERATION_sample_row(op,j) \
    (&(((op)->times)[(j)*((op)->in_count)]))
#define OPERATION_sample(op,j,i) \
    OPERATION_sample_row((op),(j))[i]

OPERATION *OPERATION_new(OP_TYPE type, const char *opt);
void OPERATION_free(OPERATION *op);

int OPERATION_malloc_results(OPERATION *op);
int OPERATION_free_results(OPERATION *op);

#define STUB(unused) \
    BIO_printf(bio_err, "%s@%s:%d\t STUB!\n", __func__, __FILE__, __LINE__)


#endif /* _HEADER_NEWSPEED_OPS_H */

/* vim: set ts=4 sw=4 tw=78 et : */
