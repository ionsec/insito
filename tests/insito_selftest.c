/* Parity check: my glibc TYPE_3 rand() replication vs the real libc rand(). */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct { int32_t r[31]; int f, k; } RSTATE;   /* glibc TYPE_3: 31-word state */

static void rs_srand(RSTATE *s, uint32_t seed) {
    int32_t word = (int32_t)seed;
    if (word == 0) word = 1;
    s->r[0] = word;                          /* r[0] = seed */
    for (int i = 1; i <= 30; i++) {          /* 30 Lehmer iterates: r[1..30] */
        int64_t w = 16807L * (int64_t)(word % 127773) - 2836L * (int64_t)(word / 127773);
        if (w < 0) w += 2147483647L;
        word = (int32_t)w;
        s->r[i] = word;
    }
    s->f = 3; s->k = 0;                      /* fptr=state[3], rptr=state[0] */
    for (int i = 0; i < 310; i++) {          /* 310 initial discards */
        s->r[s->f] = (int32_t)((uint32_t)s->r[s->f] + (uint32_t)s->r[s->k]);
        s->f = (s->f + 1) % 31; s->k = (s->k + 1) % 31;
    }
}
static uint32_t rs_rand(RSTATE *s) {
    s->r[s->f] = (int32_t)((uint32_t)s->r[s->f] + (uint32_t)s->r[s->k]);
    uint32_t out = (uint32_t)s->r[s->f] >> 1;
    s->f = (s->f + 1) % 31; s->k = (s->k + 1) % 31;
    return out;
}

int main(void) {
    struct { uint32_t seed; int n; } cases[] = {{1751524998u, 200}, {1791524998u, 200}, {42u, 500}, {0u, 50}};
    for (int s = 0; s < 4; s++) {
        RSTATE rs; rs_srand(&rs, cases[s].seed);
        srand(cases[s].seed);
        for (int i = 0; i < cases[s].n; i++) {
            uint32_t mine = rs_rand(&rs), libc = (uint32_t)rand();
            if (mine != libc) { printf("MISMATCH seed=%u i=%d mine=%u libc=%u\n", cases[s].seed, i, mine, libc); return 1; }
        }
        printf("PARITY-OK seed=%u (%d draws)\n", cases[s].seed, cases[s].n);
    }
    printf("=== glibc rand replication: ALL OK ===\n");
    return 0;
}
