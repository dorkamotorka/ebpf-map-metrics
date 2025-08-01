//go:build ignore
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

  /* -------------------------------------------
  * Figure out how many elements the map holds
  * ------------------------------------------- */
  s64 elem_cnt;

  switch (map->map_type) {
	  /* all the fixed-size “array-like” maps */
	  case BPF_MAP_TYPE_ARRAY:
	  case BPF_MAP_TYPE_PERCPU_ARRAY:
	  case BPF_MAP_TYPE_PROG_ARRAY:
	  case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
	  case BPF_MAP_TYPE_DEVMAP:
	  case BPF_MAP_TYPE_DEVMAP_HASH:
	  case BPF_MAP_TYPE_CPUMAP:
		/* every slot exists from 0..max_entries-1 */
		elem_cnt = map->max_entries;
		break;

	  default:
		/* dynamically sized -> ask the helper */
		elem_cnt = bpf_map_sum_elem_count(map);
		break;
  }

  BPF_SEQ_PRINTF(seq, "%4u %-32s %10d %10lld\n", map->id, map->name,
                 map->max_entries, elem_cnt);

  return 0;
}

char _license[] SEC("license") = "GPL";
