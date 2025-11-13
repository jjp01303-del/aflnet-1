#ifndef BASFUZZ_H
#define BASFUZZ_H

#include "types.h"

struct afl_state;
struct queue_entry;

struct basfuzz_matrix {
  u32 n;
  u32 d;
  u8* data;
};

#define BASF_MAT_AT(m, i, k) ((m)->data[(u64)(i) * (m)->d + (k)])

int basfuzz_build_matrix(struct afl_state* afl,
                         struct queue_entry** queue_array,
                         u32 queue_len,
                         u32 max_len,
                         struct basfuzz_matrix* out);

int basfuzz_compute_similarity(struct basfuzz_matrix* m,
                               double h,
                               double* beta,
                               double* gamma,
                               double* scores);
/* Pass gamma == NULL to skip the structural component. */

void basfuzz_sort_queue(struct queue_entry** queue_array,
                        u32 queue_len,
                        double* scores);

void basfuzz_free_matrix(struct basfuzz_matrix* m);

#endif /* BASFUZZ_H */
