#define BPF_NAME_LEN 16U
#define MAX_EVENTS  (128)

// Order matters!
enum map_updater {
    MAP_UPDATE,
    MAP_DELETE
} map_updater;

struct MapData {
    unsigned int map_id;
    char name[BPF_NAME_LEN];
    enum map_updater update_type;
    unsigned int pid;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int key;
    unsigned int value;
};

struct Config {
  __u16 host_port;
  __u64 host_pid;
};

// The bpf syscall has 3 arguments:
//  1. cmd:   The command/action to take (get a map handle, load a program, etc.)
//  2. uattr: A union of structs that hold the arguments for the action
//  3. size:  The size of the union
struct syscall_bpf_args {
    unsigned long long unused;
    long syscall_nr;
    int cmd;
    // bpf_attr contains the arguments to pass to the
    // various bpf commands
    union bpf_attr* uattr;
    unsigned int size;
};
