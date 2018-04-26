#include "newspeed_config.h"
#include "apps.h"
#include "apps_opt.h"
#include "newspeed_ops.h"
#include "newspeed_loop.h"
#include "newspeed_median.h"

#include <math.h> // sqrt
#include <time.h>

#ifndef OpenSSL_version
#define OpenSSL_version(a) SSLeay_version((a))
#endif /* ! defined( OpenSSL_version ) */

char *prog;
char *engine_val = "";
char **_argv = NULL;
int _argc = 0;
BIO *bio_out;
BIO *bio_json = NULL;
time_t run_date;
extern uint64_t benchmark_cost;

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENGINE,
    OPT_EVP_PKEY_KEYGEN,
    OPT_EVP_PKEY_DERIVE,
    OPT_EVP_PKEY_DSS, OPT_EVP_PKEY_SIGN, OPT_EVP_PKEY_VERIFY,
#ifdef ENABLE_OP_EVP_DIGESTSIGN
    OPT_EVP_DIGEST_DSS, OPT_EVP_DIGESTSIGN, OPT_EVP_DIGESTVERIFY,
#endif /* ENABLE_OP_EVP_DIGESTSIGN */
    OPT_NOOP,
    OPT_JSON
} OPTION_CHOICE;

const OPTIONS speed_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options]\n"},
    {OPT_HELP_STR, 1, '-', "Valid options are:\n"},
    {"help", OPT_HELP, '-', "Display this summary"},

#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif

    {"evp_pkey_keygen", OPT_EVP_PKEY_KEYGEN, 's', "Benchmark EVP_PKEY key-pair generation"},

    {"evp_pkey_derive", OPT_EVP_PKEY_DERIVE, 's', "Benchmark EVP_PKEY derive (DH) operation"},

    {"evp_pkey_dss", OPT_EVP_PKEY_DSS, 's', "Benchmark EVP_PKEY digital signature scheme (sign+verify)"},
    {"evp_pkey_sign", OPT_EVP_PKEY_SIGN, 's', "Benchmark EVP_PKEY (DSS) sign operation"},
    {"evp_pkey_verify", OPT_EVP_PKEY_VERIFY, 's', "Benchmark EVP_PKEY (DSS) verify operation"},

#ifdef ENABLE_OP_EVP_DIGESTSIGN
    {"evp_digest_dss", OPT_EVP_DIGEST_DSS, 's', "Benchmark EVP_DigestSign/DigestVerify digital signature scheme"},
    {"evp_digestsign", OPT_EVP_DIGESTSIGN, 's', "Benchmark EVP_DigestSign operation"},
    {"evp_digestverify", OPT_EVP_DIGESTVERIFY, 's', "Benchmark EVP_DigestVerify operation"},
#endif /* ENABLE_OP_EVP_DIGESTSIGN */

    {"json", OPT_JSON, '>', "Output json stats to file"},
    {"noop", OPT_NOOP, '-', "Benchmark noop operation"},

    {NULL},
};

#define MAX_QUEUED_OPERATIONS 30
OPERATION *queued_operations[MAX_QUEUED_OPERATIONS] = {NULL};
static int queued_operations_cnt = 0;

static int enqueue_operation(OP_TYPE type, const char *arg)
{
    if (queued_operations_cnt >= MAX_QUEUED_OPERATIONS ) {
        BIO_printf(bio_err,
                "%s: max amount of operations reached (%d)\n",
                prog, MAX_QUEUED_OPERATIONS);
        return 0;
    }

    OPERATION * op = OPERATION_new(type, arg);

    if (op) {
        queued_operations[queued_operations_cnt++] = op;
        return 1;
    }

    return 0;
}

#define MAX_LOADED_ENGINES 5
ENGINE *loaded_engines[] = {NULL};
static int loaded_engines_cnt = 0;

static int handle_engine(const char *engine_id)
{
    if (loaded_engines_cnt >= MAX_LOADED_ENGINES ) {
        BIO_printf(bio_err,
                "%s: max amount of -engine opts reached (%d)\n",
                prog, MAX_LOADED_ENGINES);
        return 0;
    }
    ENGINE *e = setup_engine(opt_arg(), 0);
    if (e != NULL ) {
        loaded_engines[loaded_engines_cnt++] = e;
    }
    return 1;
}

static void release_engines(void)
{
    for (int i=0; i < loaded_engines_cnt; i++) {
        release_engine(loaded_engines[i]);
    }
}

#define OVERFLOW_E(where) \
    BIO_printf(bio_err, "CRITICAL OVERFLOW COMPUTING STATS %s@%s:%d\n", \
               (where) , __FILE__, __LINE__); \
    goto end;

static uint64_t compute_variance(uint64_t *inputs, int n)
{
#if 1
    uint64_t prev=0, acc=0, var=0;
    uint64_t size = n;
    for(int i=0; i<n; i++) {
        prev=acc;
        acc += inputs[i];
        if (acc<prev) { OVERFLOW_E("acc+=x") };

        prev = var;
        var += inputs[i]*inputs[i];
        if(var<prev) { OVERFLOW_E("var+=x*x"); }
    }
    prev = acc;
    acc = acc * acc;
    if (acc<prev) { OVERFLOW_E("acc=acc*acc"); }

    prev = var;
    var = var * size;
    if(var<prev) { OVERFLOW_E("var=var*size"); }

    var = (var - acc)/(size*size);
#else
    uint64_t prev=0, k = UINT64_MAX;
    uint64_t ex=0, ex2=0;
    uint64_t size = n;

    // select k as the minimum to avoid negative (inputs[i]-k)
    for (int i=0; i<n; i++) {
        if (inputs[i]<k) k = inputs[i];
    }
    for (int i=0; i<n; i++) {
        ex  += inputs[i] - k;
        ex2 += (inputs[i]-k)*(inputs[i]-k);
    }
    prev = ex2;
    ex2 *= size;
    if (ex2<prev) { OVERFLOW_E("ex2*=size"); }

    prev = ex;
    ex = ex * ex;
    if (ex<prev) { OVERFLOW_E("ex=ex*ex"); }

    uint64_t var = (ex2 - ex)/(size*size);
#endif

    return var;
end:
    return 1111111111111111111; // the 64-bit longest base10 string of "1"s
}

static int OPERATION_results_stats(OPERATION *op)
{
    int ret = 0;
    if(!op) goto end;

    int out_count = op->out_count;
    int in_count = op->in_count;

    uint64_t *variances = app_malloc(out_count*sizeof(*variances), "variances");
    uint64_t *min_values = app_malloc(out_count*sizeof(*min_values), "min_values");
    if (!variances || !min_values) goto end;

    uint64_t min_min=UINT64_MAX, out_acc=0, tot_var=0, abs_max_dev=0;
    uint64_t prev=0, prev_min=0, spurious=0;
    for(int j=0; j < out_count; j++) {
        uint64_t min=UINT64_MAX, max=0, acc=0;
        uint64_t var = 0; //variance

        for (int i=0; i < in_count; i++) {
            uint64_t val = OPERATION_sample(op,j,i);
            if (val<min) min = val;
            if (val>max) max = val;

            prev = acc;
            acc += val;
            if(acc<prev) { OVERFLOW_E("acc+=val"); }
        }
        if (prev_min !=0 && prev_min>min) spurious++;
        min_values[j] = min;
        if (min < min_min) min_min = min;

        uint64_t max_dev = max - min;
        if (max_dev > abs_max_dev) abs_max_dev = max_dev;

        out_acc += acc; // outer accumulator
        double avg = (double)(acc)/in_count;

        // variance
        var = compute_variance(OPERATION_sample_row(op,j), in_count);
        variances[j] = var;
        tot_var += var;

        prev_min = min;
#if 0
        BIO_printf(bio_out,
                "l%03d: var=%" PRIu64 ",max_dev=%" PRIu64 ",min=%" PRIu64 ",avg=%lf\n",
                j,var,max_dev,min,avg);
#endif
    }
    op->stats.spurious = spurious;
    op->stats.tot_var = tot_var;
    op->stats.abs_max_dev = abs_max_dev;
    op->stats.var_var = compute_variance(variances, out_count);
    op->stats.var_min = compute_variance(min_values, out_count);
    op->stats.min_min = min_min;
    op->stats.avg = (double)(out_acc) /(in_count*out_count);
    op->stats.std = sqrt((double)(tot_var));
    op->stats.rel_std = 100 * op->stats.std / op->stats.avg;

    op->stats.median = median(op->times, in_count*out_count);

    op->stats.guard = 1; // mark as valid

    ret = 1;
end:
    if (variances)
        OPENSSL_free(variances);
    if (min_values)
        OPENSSL_free(min_values);
    return ret;
}

static int OPERATION_json_results(OPERATION *op, BIO *bio)
{
    int ret = 0;
    if (!op || op->success != 1) goto end;

    static char op_id[80];
    BIO_snprintf(op_id, 80, "%p", op);
    BIO_printf(bio, "{"
                    "\"bits\": %d, "
                    "\"alg_name\": \"%s\", "
                    "\"op_name\": \"%s\", "
                    "\"op_id\": \"%s\", "
                    "\"out_count\": %d, "
                    "\"in_count\": %d, "
                    "\"iterations_per_sample\": %d, ",
                    op->bits, op->alg_name, op->op_meth->name, op_id,
                    op->out_count, op->in_count, ITERATIONS_PER_SAMPLE);

    OP_STATS *stats = &(op->stats);
    if (1 != stats->guard) {
        if (!OPERATION_results_stats(op)) {
            goto end;
        }
    }

#if 0
    BIO_printf(bio, "\"stats\": { "
                    "\"spurious_min\": %" PRIu64 ", "
                    "\"tot_var\": %" PRIu64 ", "
                    "\"absolute_max_deviation\": %" PRIu64 ", "
                    "\"variance_variances\": %" PRIu64 ", "
                    "\"variance_minimums\": %" PRIu64 ", "
                    "\"minimum_minimums\": %" PRIu64 ", "
                    "\"median\": %" PRIu64 ", "
                    "\"mean\": %.2lf, "
                    "\"st_dev\": %.2lf, "
                    "\"relative_st_dev\": %.2lf"
                    "}, ",
                    stats->spurious, stats->tot_var, stats->abs_max_dev,
                    stats->var_var, stats->var_min, stats->min_min,
                    stats->median,
                    stats->avg, stats->std, stats->rel_std);
#endif


    BIO_printf(bio, "\"RUNS\": [ ");
    for(int j=0; j<op->out_count; j++) {
        BIO_printf(bio, "%s{ \"j\": %d, "
                        "\"values\": [ ",
                        (j>0?", ":""), j);
        for(int i=0; i<op->in_count; i++) {
            BIO_printf(bio, "%s%" PRIu64 , (i>0?", ":""), OPERATION_sample(op, j, i));
        }
        BIO_printf(bio, "] }");
    }
    BIO_printf(bio, "] ");

    BIO_printf(bio, "}");

    ret = 1;
end:
    return ret;
}


static int OPERATION_print_results(OPERATION *op, BIO *bio)
{
    int ret = 0;
    if (!op || op->success != 1) goto end;

#define LINE_PREAMBLE_LEN 60
    static char line_preamble[LINE_PREAMBLE_LEN+1];
    BIO_snprintf(line_preamble, LINE_PREAMBLE_LEN+1,
                 "%d bits %s %s:",
                 op->bits, op->alg_name, op->op_meth->name);

    OP_STATS *stats = &(op->stats);
    if (1 != stats->guard) {
        if (!OPERATION_results_stats(op)) {
            goto end;
        }
    }

    BIO_printf(bio,
            "%s spu=%" PRIu64 ",tot_var=%" PRIu64 ",abs_max_dev=%" PRIu64
            ",var_var=%" PRIu64 ",var_min=%" PRIu64 ",min_min=%" PRIu64
            ",median=%" PRIu64
            ",avg=%.2lf,std=%.2lf,rel_std=%.2lf%%\n",
            line_preamble,
            stats->spurious, stats->tot_var, stats->abs_max_dev,
            stats->var_var, stats->var_min, stats->min_min,
            stats->median,
            stats->avg, stats->std, stats->rel_std);
    BIO_flush(bio);

    ret = 1;
end:
    return ret;
}

void do_setup(OPERATION *operations[], int n)
{
    for(int i=0; i<n; i++) {
        OPERATION *op = operations[i];
        if (!op->setup(op)) {
            BIO_printf(bio_err, "%s: setup failed for %s %s\n", prog,
                    op->op_meth->name, op->alg_name);
        }
    }
}

#ifdef CALIBRATE

#define MAX_CALIBRATE_ROUNDS 100
#define CALIBRATION_TARGET(stat) \
    (((stat).spurious == 0) && ((stat).var_min == 0) && ((stat).var_var == 0))
int do_calibrate(int verbose)
{
    int ret = 0, i;
    OPERATION *op = OPERATION_new(OP_NOOP,"calibration");
    if (NULL == op) goto end;
    if(0 == verbose) {
        op->quiet = 1;
    }
    BIO_printf(bio_err, "CALIBRATING...\n");
    BIO_flush(bio_err);

#ifdef CALIBRATE_INCREASE_RESOLUTION
    // increase resolution for calibration
    OPERATION_free_results(op);
    //op->out_count *= 10;
    op->in_count *= CALIBRATE_INCREASE_RESOLUTION;
    OPERATION_malloc_results(op);
#endif /* CALIBRATE_INCREASE_RESOLUTION */

    uint64_t var_min=UINT64_MAX;
    for(i=0; i<MAX_CALIBRATE_ROUNDS ; i++) {
        if (!OPERATION_benchmark(op)) {
            BIO_printf(bio_err, "benchmark failed\n");
            goto end;
        }
        if (!OPERATION_results_stats(op)) {
            BIO_printf(bio_err, "stats failed\n");
            goto end;
        }
        if (verbose>1) OPERATION_print_results(op, bio_err);

        if(CALIBRATION_TARGET(op->stats)) break;
    }
    if (i>=MAX_CALIBRATE_ROUNDS) goto end;

    benchmark_cost = op->stats.min_min;
    ret = 1;
end:
    if(op) {
        OPERATION_free(op);
        op = NULL;
    }
    return ret;
}

#endif /* CALIBRATE */

void do_benchmark(OPERATION *operations[], int n)
{
    for(int i=0; i<n; i++) {
        if (NULL == operations[i]->run)
            continue; //skip
        OPERATION_benchmark(operations[i]);
    }
}

void do_print_results(OPERATION *operations[], int n)
{
    for(int i=0; i<n; i++) {
        if (NULL == operations[i]->run)
            continue; //skip
        OPERATION_print_results(operations[i], bio_out);
    }
}

#include <string.h> // strcpy
void do_json_results(OPERATION *operations[], int n)
{
    int is_first = 1;
    int pid = getpid();
    static char hostname[256] = { 0 };
    if ( 0 != gethostname( hostname, sizeof(hostname)) ) {
        strcpy(hostname, "N/A");
    }
    hostname[sizeof(hostname)-1] = 0;
    static char date_b[256] = { 0 };
    if ( 0 == strftime(date_b, 256, "%Y-%m-%d %H:%M:%S %z", gmtime(&run_date)) ) {
        BIO_printf(bio_err, "Failed to represent the date\n");
        strcpy(date_b, "N/A");
    }

    BIO_printf(bio_json, "{"
                         "\"pid\": %d, "
                         "\"machine\": \"%s\", "
                         "\"engine\": \"%s\", "
                         "\"date\": \"%s\", "
                         "\"openssl_v\": \"0x%08lx\", "
                         "\"openssl_v_txt\": \"%s\", "
                         "\"argv\": [ ",
                         pid, hostname, engine_val,
                         date_b,
                         OPENSSL_VERSION_NUMBER,
                         OpenSSL_version(0));
    for (int i=0; i<_argc; i++ ) {
        BIO_printf(bio_json, "%s\"%s\"",
                             (i>0?", ":""),
                             _argv[i]);
    }
    BIO_printf(bio_json, " ], ");
    BIO_printf(bio_json, "\"operations\": [ ");

    for(int i=0; i<n; i++) {
        if (NULL == operations[i]->run || operations[i]->success != 1)
            continue; //skip
        if (!is_first) {
            BIO_printf(bio_json, ",\n");
        } else {
            is_first = 0;
        }
        OPERATION_json_results(operations[i], bio_json);
    }
    BIO_printf(bio_json, " ] }");

    BIO_flush(bio_json);

    BIO_free_all(bio_json); bio_json = NULL;
}

static int speed_main(int argc, char **argv)
{
    int ret = 1;
    run_date = time(NULL);
    OPTION_CHOICE o;
    prog = opt_init(argc, argv, speed_options);

    if (argc <= 1) {
        goto opthelp;
    }

#if 0
    if(!enqueue_operation(OP_NO_OP, "NOOP")) {
        BIO_printf(bio_err, "Failed to enqueue noop\n");
    }
#endif

#define FAILED_OPT(arg) \
    BIO_printf(bio_err, "Failed parsing option: \"%s %s\"\n", opt_flag(), (arg))

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
            case OPT_EOF:
            case OPT_ERR:
opterr:
                ret = 25;
                BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
                goto end;
            case OPT_HELP:
                ret = 0;
opthelp:
                opt_help(speed_options);
                goto end;

            case OPT_EVP_PKEY_KEYGEN:
                if(!enqueue_operation(OP_EVP_PKEY_KEYGEN, opt_arg())) { FAILED_OPT(opt_arg()); }
                break;

            case OPT_EVP_PKEY_DERIVE:
                if(!enqueue_operation(OP_EVP_PKEY_DERIVE, opt_arg())) { FAILED_OPT(opt_arg()); }
                break;

            case OPT_EVP_PKEY_DSS:
                if(!enqueue_operation(OP_EVP_PKEY_SIGN, opt_arg())) { FAILED_OPT(opt_arg()); }
                if(!enqueue_operation(OP_EVP_PKEY_VERIFY, opt_arg())) { FAILED_OPT(opt_arg()); }
                break;
            case OPT_EVP_PKEY_SIGN:
                if(!enqueue_operation(OP_EVP_PKEY_SIGN, opt_arg())) { FAILED_OPT(opt_arg()); }
                break;
            case OPT_EVP_PKEY_VERIFY:
                if(!enqueue_operation(OP_EVP_PKEY_VERIFY, opt_arg())) { FAILED_OPT(opt_arg()); }
                break;

#ifdef ENABLE_OP_EVP_DIGESTSIGN
            case OPT_EVP_DIGEST_DSS:
                if(!enqueue_operation(OP_EVP_DIGESTSIGN, opt_arg())) { FAILED_OPT(opt_arg()); }
                if(!enqueue_operation(OP_EVP_DIGESTVERIFY, opt_arg())) { FAILED_OPT(opt_arg()); }
                break;
            case OPT_EVP_DIGESTSIGN:
                if(!enqueue_operation(OP_EVP_DIGESTSIGN, opt_arg())) { FAILED_OPT(opt_arg()); }
                break;
            case OPT_EVP_DIGESTVERIFY:
                if(!enqueue_operation(OP_EVP_DIGESTVERIFY, opt_arg())) { FAILED_OPT(opt_arg()); }
                break;
#endif /* ENABLE_OP_EVP_DIGESTSIGN */


            case OPT_NOOP:
                if(!enqueue_operation(OP_NOOP, "")) { FAILED_OPT(""); }
                break;

            case OPT_ENGINE:
                if (!handle_engine(opt_arg()))
                    goto end;
                engine_val = opt_arg();
                break;
            case OPT_JSON:
                if (NULL == (bio_json = BIO_new_file(opt_arg(), "w"))) {
                    goto end;
                }
                break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();
#if 1
    if (argc > 0 ) {
        BIO_printf(bio_err, "%s: Unknown option %s\n", prog, *argv);
        goto opterr;
    }
#else
    /* Remaining arguments */
    for (; *argv; argv++) {
        BIO_printf(bio_err, "%s: Unknown option %s\n", prog, *argv);
        goto end;
    }
#endif

    // SETUP ALL THE OPERATIONS
    do_setup(queued_operations, queued_operations_cnt);

#ifdef CALIBRATE
    // CALIBRATE (get the cost of the benchmarking mechanism)
    if (!do_calibrate(2)) {
        BIO_printf(bio_err, "FATAL: calibration failed\n");
        goto end;
    }
#endif /* CALIBRATE */

    // BENCHMARK EACH OPERATION
    do_benchmark(queued_operations, queued_operations_cnt);

    // PRINT RESULTS
    do_print_results(queued_operations, queued_operations_cnt);

    // JSON OUTPUT
    if (bio_json) {
        do_json_results(queued_operations, queued_operations_cnt);
    }

    ret = 0;

end:
    ERR_print_errors(bio_err);
    for(int i=0; i<queued_operations_cnt; i++) {
        OPERATION_free(queued_operations[i]);
    }
    release_engines();
    return (ret);
}



#include <string.h>

int main(int argc, char **argv)
{
    int ret = 0;

    _argc = argc;
    _argv = malloc(_argc * sizeof(char *));
    for (int i=0; i<_argc; i++) {
        _argv[i] = strdup(argv[i]);
    }

    apps_init();
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    ret = speed_main(argc, argv);

    BIO_free_all(bio_err);
    BIO_free_all(bio_out);


    for (int i=0; i<_argc; i++) {
        free(_argv[i]);
    }
    free(_argv);

    return ret;
}

/* vim: set ts=4 sw=4 tw=78 et : */
