//go:build ignore
#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"
#include "sync.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 10240);
} array_map SEC(".maps");

/* BPF ringbuf map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} map_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 10240);
} hash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32);
    __type(key, int);
    __type(value, int);
} lru_hash_map SEC(".maps");

#define MEM_READ(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

static void __always_inline
log_map_update(struct bpf_map* updated_map, unsigned int *pKey, unsigned int *pValue, enum map_updater update_type)
{ 
  // Get basic info about the map
  uint32_t map_id = MEM_READ(updated_map->id);
  uint32_t key_size = MEM_READ(updated_map->key_size);
  uint32_t value_size = MEM_READ(updated_map->value_size);
 
  struct MapData *out_data;
  out_data = bpf_ringbuf_reserve(&map_events, sizeof(*out_data), 0);
	if (!out_data) {
    bpf_printk("Failed to reserve mem in ringbuf\n");
    return;
  }

  bpf_probe_read_str(out_data->name, BPF_NAME_LEN, updated_map->name);
  bpf_probe_read(&out_data->key, sizeof(*pKey), pKey);
  out_data->key_size = key_size;
  if (pValue != 0) {
    bpf_probe_read(&out_data->value, sizeof(*pValue), pValue);
    out_data->value_size = value_size;
  }
  out_data->map_id = map_id;
  out_data->pid = (unsigned int)(bpf_get_current_pid_tgid() >> 32);
  out_data->update_type = update_type;

  // Write data to be processed in userspace
  bpf_ringbuf_submit(out_data, 0);
}

// We use fexit instead of fentry, because ret also tells us whether the operation was actually successful or not
// Unsuccessful operation is e.g. deleting a key that doesn't exists 

SEC("fexit/htab_map_update_elem")
int BPF_PROG(bpf_prog_kern_hmapupdate, struct bpf_map *map, void *key, void *value, u64 map_flags, long ret) {
  bpf_printk("htab_map_update_elem: %d\n", ret);

  if (ret != 0) {
    bpf_printk("Hash table wasn't updated");
    return 0;
  }

  log_map_update(map, key, value, MAP_UPDATE);
  return 0;
}

SEC("fexit/htab_map_delete_elem")
int BPF_PROG(bpf_prog_kern_hmapdelete, struct bpf_map *map, void *key, long ret) {
  bpf_printk("htab_map_delete_elem: %d\n", ret);

  if (ret != 0) {
    bpf_printk("Hash table wasn't updated");
    return 0;
  }

  log_map_update(map, key, 0, MAP_DELETE);
  return 0;
}

SEC("fexit/htab_lru_map_update_elem")
int BPF_PROG(bpf_prog_kern_lruhmapupdate, struct bpf_map *map, void *key, void *value, u64 map_flags, long ret) {
  bpf_printk("htab_lru_map_update_elem: %d\n", ret);

  if (ret != 0) {
    bpf_printk("LRU Hash table wasn't updated");
    return 0;
  }

  log_map_update(map, key, value, MAP_UPDATE);
  return 0;
}

SEC("fexit/htab_lru_map_delete_elem")
int BPF_PROG(bpf_prog_kern_lruhmapdelete, struct bpf_map *map, void *key, long ret) {
  bpf_printk("htab_lru_map_delete_elem: %d\n", ret);

  if (ret != 0) {
    bpf_printk("LRU Hash table wasn't updated");
    return 0;
  }

  log_map_update(map, key, 0, MAP_DELETE);
  return 0;
}

SEC("fexit/array_map_update_elem")
int BPF_PROG(bpf_prog_kern_arraymapupdate, struct bpf_map *map, void *key, void *value, u64 map_flags, long ret) {
  bpf_printk("array_map_update_elem: %d\n", ret);

  if (ret != 0) {
    bpf_printk("Array wasn't updated");
    return 0;
  }

  log_map_update(map, key, value, MAP_UPDATE);
  return 0;
}

SEC("fexit/array_map_delete_elem")
int BPF_PROG(bpf_prog_kern_arraymapdelete, struct bpf_map *map, void *key, long ret) {
  bpf_printk("array_map_delete_elem: %d\n", ret);

  if (ret != 0) {
    bpf_printk("Array wasn't updated");
    return 0;
  }

  log_map_update(map, key, 0, MAP_DELETE);
  return 0;
}
