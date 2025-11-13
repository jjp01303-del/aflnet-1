#include "basfuzz.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include "alloc-inl.h"
#include "debug.h"
#include "afl-fuzz.h"

#define BASFUZZ_GAMMA_LIMIT 512

static int basfuzz_load_row(struct queue_entry* q, u32 max_len, u8* dst) {

  if (!dst) return -1;
  memset(dst, 0, max_len);

  if (!q || !q->fname || !max_len) return 0;

  u32 copy_len = q->len < max_len ? q->len : max_len;
  if (!copy_len) return 0;

  s32 fd = open((char*)q->fname, O_RDONLY);
  if (fd < 0) {
    WARNF("basfuzz: unable to open '%s': %s", q->fname, strerror(errno));
    return -1;
  }

  u32 remaining = copy_len;
  u8* ptr       = dst;

  while (remaining) {

    s32 r = read(fd, ptr, remaining);
    if (r < 0) {
      if (errno == EINTR || errno == EAGAIN) continue;
      WARNF("basfuzz: read error on '%s': %s", q->fname, strerror(errno));
      close(fd);
      return -1;
    }

    if (!r) break;

    ptr += r;
    remaining -= r;

  }

  close(fd);

  return 0;

}

int basfuzz_build_matrix(struct afl_state* afl,
                         struct queue_entry** queue_array,
                         u32 queue_len,
                         u32 max_len,
                         struct basfuzz_matrix* out) {

  (void)afl;

  if (!out) return -1;

  out->n    = 0;
  out->d    = 0;
  out->data = NULL;

  if (!queue_len || !max_len || !queue_array) return 0;

  u64 total = (u64)queue_len * (u64)max_len;
  if (total > UINT32_MAX) {
    WARNF("basfuzz: matrix size %llu exceeds allocator limit", total);
    return -1;
  }

  out->data = ck_alloc((u32)total);
  out->n    = queue_len;
  out->d    = max_len;

  for (u32 i = 0; i < queue_len; ++i) {

    struct queue_entry* q = queue_array[i];
    u8*                 row = out->data + (u64)i * max_len;

    if (basfuzz_load_row(q, max_len, row)) {
      /* Leave the row zeroed if loading fails. */
      continue;
    }

  }

  return 0;

}

static void basfuzz_compute_beta(struct basfuzz_matrix* m, double* beta) {

  if (!m || !beta || !m->data || !m->n || !m->d) return;

  for (u32 i = 0; i < m->n; ++i) beta[i] = 0.0;

  for (u32 k = 0; k < m->d; ++k) {

    u32 counts[256];
    memset(counts, 0, sizeof(counts));

    for (u32 i = 0; i < m->n; ++i) {
      u8 val = BASF_MAT_AT(m, i, k);
      counts[val]++;
    }

    for (u32 i = 0; i < m->n; ++i) {
      u8     val    = BASF_MAT_AT(m, i, k);
      double share  = (double)counts[val] / (double)m->n;
      beta[i] += share;
    }

  }

}

static void basfuzz_compute_gamma(struct basfuzz_matrix* m, double* gamma) {

  if (!m || !gamma || !m->data || !m->n || !m->d) return;

  for (u32 i = 0; i < m->n; ++i) gamma[i] = 0.0;

  if (m->n > BASFUZZ_GAMMA_LIMIT) {
    /* Avoid excessive O(n^2 * d) cost for very large queues. */
    return;
  }

  double denom = (double)m->d;

  for (u32 i = 0; i < m->n; ++i) {

    u8* row_i = m->data + (u64)i * m->d;

    for (u32 j = i; j < m->n; ++j) {

      u8* row_j = m->data + (u64)j * m->d;
      u32 eq    = 0;

      for (u32 k = 0; k < m->d; ++k)
        if (row_i[k] == row_j[k]) eq++;

      double contrib = (double)eq / denom;
      gamma[i] += contrib;
      if (j != i) gamma[j] += contrib;

    }

  }

}

int basfuzz_compute_similarity(struct basfuzz_matrix* m,
                               double h,
                               double* beta,
                               double* gamma,
                               double* scores) {

  if (!m || !beta || !gamma || !scores) return -1;

  if (h < 0.0 || h > 1.0) h = 0.5;

  basfuzz_compute_beta(m, beta);
  basfuzz_compute_gamma(m, gamma);

  for (u32 i = 0; i < m->n; ++i)
    scores[i] = h * beta[i] + (1.0 - h) * gamma[i];

  return 0;

}

struct basfuzz_item {
  struct queue_entry* qe;
  double              score;
};

static int basfuzz_item_cmp(const void* a, const void* b) {

  const struct basfuzz_item* pa = (const struct basfuzz_item*)a;
  const struct basfuzz_item* pb = (const struct basfuzz_item*)b;

  if (pa->score < pb->score) return -1;
  if (pa->score > pb->score) return 1;
  if (pa->qe < pb->qe) return -1;
  if (pa->qe > pb->qe) return 1;
  return 0;

}

void basfuzz_sort_queue(struct queue_entry** queue_array,
                        u32 queue_len,
                        double* scores) {

  if (!queue_array || !scores || queue_len < 2) return;

  struct basfuzz_item* items = ck_alloc(sizeof(struct basfuzz_item) * queue_len);

  for (u32 i = 0; i < queue_len; ++i) {
    items[i].qe    = queue_array[i];
    items[i].score = scores[i];
  }

  qsort(items, queue_len, sizeof(struct basfuzz_item), basfuzz_item_cmp);

  for (u32 i = 0; i < queue_len; ++i) queue_array[i] = items[i].qe;

  ck_free(items);

}

void basfuzz_free_matrix(struct basfuzz_matrix* m) {

  if (!m) return;

  if (m->data) {
    ck_free(m->data);
    m->data = NULL;
  }

  m->n = 0;
  m->d = 0;

}
