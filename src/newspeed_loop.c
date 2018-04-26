#include "newspeed_config.h"
#include "newspeed_loop.h"

#ifndef SAMPLING
    #error SAMPLING is not defined
#endif

#include "newspeed_ops.h"

#include <inttypes.h>
#include <string.h>
#include <openssl/crypto.h>

#include "apps.h"
extern const char *prog;

uint64_t benchmark_cost = 0;

#ifdef NOOP
static int measured_noop(int *ptr)
{
    *ptr = 1;
    return 1;
}
#endif

#if (SAMPLING == SAMPLING_INTEL_WHITEPAPER )
/* Inspired by:
 * https://www.intel.de/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf
 */

#define MEASURE_START() \
    asm volatile ( \
        "CPUID\n\t" \
        "RDTSC\n\t" \
        "mov %%edx, %0\n\t" \
        "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::"%rax", "%rbx", "%rcx", "%rdx")

#define MEASURE_END() \
    asm volatile ( \
        "RDTSCP\n\t" \
        "mov %%edx, %0\n\t" \
        "mov %%eax, %1\n\t": "=r" (cycles_high1), "=r" (cycles_low1)::"%rax", "%rbx", "%rcx", "%rdx")

#endif /* SAMPLING == SAMPLING_INTEL_WHITEPAPER */

#if (SAMPLING == SAMPLING_SUPERCOP )
// check SUPERCOP and https://github.com/BLAKE2/BLAKE2/blob/master/bench/bench.c
inline static uint64_t cpucycles(void)
{
    uint64_t result;
    __asm__ __volatile__(
            ".byte 15;.byte 49\n" // RDTSC (original code in supercop/BLAKE)
            "shlq $32,%%rdx\n"
            "orq %%rdx,%%rax\n"
            : "=a" ( result ) ::  "%rdx"
            );
    return result;
}
#define MEASURE_START() \
    start = cpucycles();
#define MEASURE_END() \
    end = cpucycles();

#endif /* SAMPLING == SAMPLING_SUPERCOP */

#if ( SAMPLING == SAMPLING_MODIFIED_SUPERCOP )

// supercop code modified
#define CPUCYCLES(result) \
    __asm__ __volatile__( \
            "lfence\n" \
            "RDTSCP\n" \
            "shlq $32,%%rdx\n" \
            "orq %%rdx,%%rax\n" \
            : "=a" ( (result) ) ::  "%rdx" \
            )

#define MEASURE_START() \
    CPUCYCLES(start)
#define MEASURE_END() \
    CPUCYCLES(end);

#endif /* SAMPLING == SAMPLING_MODIFIED_SUPERCOP */

#if ( SAMPLING == SAMPLING_PERF )

/**
 *  lifted from here:
 * http://neocontra.blogspot.fi/2013/05/user-mode-performance-counters-for.html
 */

/*
 * constructor and destructor: https://gcc.gnu.org/onlinedocs/gcc-4.7.1/gcc/Function-Attributes.html
 * The constructor attribute causes the function to be called automatically
 * before execution enters main (). Similarly, the destructor attribute causes
 * the function to be called automatically after main () has completed or exit
 * () has been called. Functions with these attributes are useful for
 * initializing data that will be used implicitly during the execution of the
 * program.
 */

/* man page about perf_event
 * http://man7.org/linux/man-pages/man2/perf_event_open.2.html
 */

#include <asm/unistd.h>
#include <linux/perf_event.h>

static int cpucycles_fd = -1;

__attribute__((constructor)) static void perf_event_init(void)
{
    static struct perf_event_attr attr;
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    if (-1 == (cpucycles_fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0))) {
        fprintf(stderr, "Error opening leader %llx\n", attr.config);
        fprintf(stderr,
                "\tthis might be related to insufficient capabilities: "
                "try running as root, adding CAP_SYS_ADMIN capability or "
                "with `echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid`\n");
        exit(EXIT_FAILURE);
    }
}

__attribute__((destructor)) static void perf_event_fini(void)
{
    close(cpucycles_fd);
}

inline static uint64_t cpucycles(void)
{
    uint64_t  result = 0;
    if (read(cpucycles_fd, &result, sizeof(result)) < sizeof(result)) return 0;
    return result;
}

#define MEASURE_START() \
    start = cpucycles();
#define MEASURE_END() \
    end = cpucycles();

#endif /* SAMPLING == SAMPLING_PERF */

int OPERATION_benchmark(OPERATION *op)
{
    int i, j;
#ifdef HYPERLOOP
    int h;
#endif /* HYPERLOOP */
#ifdef RDTSC
    unsigned cycles_low, cycles_high, cycles_low1, cycles_high1;
#endif /* RDTSC */
    uint64_t start, end, measure;

    int bound_of_loop = op->out_count;
    int size_of_stat = op->in_count;
    uint64_t total_cycles = 0;

    //memset(&(op->stats),0,sizeof(op->stats));
    op->stats.guard = 0; // mark as dirty

    if (!op->quiet) {
        uint64_t tot_ops = ((uint64_t)(bound_of_loop)*size_of_stat)<<(HYPERLOOP_B);
        BIO_printf(bio_err, "Running %" PRIu64 " times %d bit %s %s... ",
                   tot_ops, op->bits, op->alg_name, op->op_meth->name);
        BIO_flush(bio_err);
    }

    void *data = op->data;
    int (*run_function)(int i, void *data) = op->run;
    int (*pre_run)(void *data) = op->pre_run;
    int (*post_run)(void *data) = op->post_run;
    int /*volatile*/ ret = 0; //FIXME: volatile?
#ifdef NOOP
    int var = 0;
#endif

    /* Warm up */
    MEASURE_START();
    MEASURE_END();
    MEASURE_START();
    MEASURE_END();
    MEASURE_START();
    MEASURE_END();
    MEASURE_START();
    MEASURE_END();

    for (j=0; j<bound_of_loop; j++) {
        for (i=0; i<size_of_stat; i++) {
            // PRE-RUN
            if (pre_run && !pre_run(data)) {
                BIO_printf(bio_err, "%s: PRE-RUN ERROR IN THE BENCHMARK LOOP\n", prog);
                return 0;
            }
            ret = 0;

            MEASURE_START();
            // CALL THE FUNCTION HERE
#ifdef HYPERLOOP
            for(h=0; h<HYPERLOOP_N; h++) {
#endif /* HYPERLOOP */
#ifndef NOOP
                ret += run_function(h, data);
#else
                ret += measured_noop(h, &var);
#endif
#ifdef HYPERLOOP
            }
#endif /* HYPERLOOP */
            MEASURE_END();

            if (ret!=HYPERLOOP_N) {
                BIO_printf(bio_err, "%s: benchmarked function failed\n", prog);
                ERR_print_errors(bio_err);
                return 0;
            }

#ifdef RDTSC
            start = ( ((uint64_t)cycles_high << 32) | cycles_low );
            end   = ( ((uint64_t)cycles_high1 << 32) | cycles_low1 );
#endif /* RDTSC */
            measure = end - start;

            if ( end < start || HYPERLOOP_DIVIDE(measure) < benchmark_cost ) {
                BIO_printf(bio_err, "%s: CRITICAL ERROR IN THE BENCHMARK LOOP\n", prog);
                return 0;
            } else {
                OPERATION_sample(op, j, i) = HYPERLOOP_DIVIDE(measure)-benchmark_cost;
                total_cycles += measure;
            }

            // POST-RUN
            if (post_run && !post_run(data)) {
                BIO_printf(bio_err, "%s: POST-RUN ERROR IN THE BENCHMARK LOOP\n", prog);
                return 0;
            }
        }
    }

    if (!op->quiet) {
        BIO_printf(bio_err, "%" PRIu64 " cycles\n",
                   total_cycles);
    }

    op->success = 1;

    return 1;
}

/* vim: set ts=4 sw=4 tw=78 et : */
