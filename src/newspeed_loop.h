#ifndef HEADER_NEWSPEED_LOOP_H
#define HEADER_NEWSPEED_LOOP_H

#include "newspeed_ops.h"

#ifdef HYPERLOOP
    #define HYPERLOOP_B HYPERLOOP
    #define HYPERLOOP_N (1<<HYPERLOOP_B)
    #define HYPERLOOP_DIVIDE(m) ((m)>>HYPERLOOP_B)
#else
    #define HYPERLOOP_B 0
    #define HYPERLOOP_N 1
    #define HYPERLOOP_DIVIDE(m) (m)
#endif /* HYPERLOOP */

#define ITERATIONS_PER_SAMPLE HYPERLOOP_N

int OPERATION_benchmark(OPERATION *op);

#endif /* HEADER_NEWSPEED_LOOP_H */
