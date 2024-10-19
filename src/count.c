// go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

__s64 bpf_map_sum_elem_count(struct bpf_map *map) __ksym;

SEC("iter/bpf_map")
int dump_bpf_map(struct bpf_iter__bpf_map *ctx) {
  struct seq_file *seq = ctx->meta->seq;
  __u64 seq_num = ctx->meta->seq_num;
  struct bpf_map *map = ctx->map;

  if (!map) {
    return 0;
  }

  BPF_SEQ_PRINTF(seq, "%4u %-16s %10d %10lld\n", map->id, map->name,
                 map->max_entries, bpf_map_sum_elem_count(map));

  return 0;
}

char _license[] SEC("license") = "GPL";
