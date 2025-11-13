#ifndef AFL_FUZZ_H
#define AFL_FUZZ_H

#include "types.h"

typedef enum {
  MUT_MODE_DEFAULT = 0,
  MUT_MODE_LEVY    = 1 << 0,
  MUT_MODE_SA      = 1 << 1,
  MUT_MODE_DIR     = 1 << 2,
  MUT_MODE_TWISE   = 1 << 3,
  MUT_MODE_MI      = 1 << 4,
  MUT_MODE_BANDIT  = 1 << 5
} mutator_mode_t;

typedef struct bandit_arm {
  u64    pulls;
  u64    rewards;
  double value;
} bandit_arm_t;

typedef struct afl_state {
  u32 mutator_modes;
  u8  debug;

  /* Simulated annealing (SA-Mutate) parameters */
  u32    sa_steps;
  u32    sa_min_stack;
  u32    sa_max_stack;
  u32    sa_noise_ops;
  double sa_T0;
  double sa_Tmin;
  double sa_decay;
  u64    sa_iteration_count;

  /* MI-guided havoc data */
  u32     mi_max_len;
  u32     mi_record_cap;
  u32     mi_current_count;
  u32    *mi_current_offsets;
  u32    *mi_mut_cnt;
  u32    *mi_hit_cnt;
  double *mi_weight;
  double  mi_weight_total;
  double  mi_base_hit;
  double  mi_base_mut;
  u64     iteration_prev_total;
  u8      collect_offsets;

  /* t-wise mutator structures */
  u32   twise_strength;
  u32   twise_max_positions;
  u32   twise_max_templates;
  u32   twise_execs_per_template;
  u32   twise_pos_cnt;
  u32  *twise_positions;
  u32  *twise_importance;
  u8   *twise_templates;
  u32   twise_templates_cnt;
  u32   twise_last_len;
  u8    twise_dirty;

  /* Bandit scheduler (operator selection) */
  u32          bandit_max_arms;
  double       bandit_explore;
  bandit_arm_t *bandit_arms;
  u64          bandit_total_pulls;
  u32          bandit_op_cap;
  u32          bandit_op_count;
  u32         *bandit_op_history;

  /* Directional mutation (diff dictionary) */
  u32         dir_dict_size;
  u32         dir_max_diff;
  u32         dir_max_combine;
  u32         dir_execs_per_combo;
  u32         dir_dict_count;
  u32         dir_dict_next;
  const u8   *dir_base_ptr;
  u32         dir_base_len;
  u8         *dir_candidate_ptr;
  u32         dir_candidate_len;
  u8          dir_collect;
  u32        *dir_entry_len;
  u32        *dir_entry_pos;
  u8         *dir_entry_val;
  u32        *dir_combo_cache;
  u32        *dir_temp_positions;
  u8         *dir_temp_values;

  /* BASFuzz scheduler configuration */
  u8     use_basfuzz;
  double basfuzz_h;
  u32    basfuzz_max_len;
  u32    basfuzz_interval;
  u64    basfuzz_counter;
  u32    basfuzz_max_seeds;

} afl_state_t;

#endif /* AFL_FUZZ_H */
