# ebpf-map-metrics

## Development Status

This project is currently under development.

It requires `6.6+` Linux Kernel, due to `bpf_map_sum_elem_count` kfunc.

## How to Run

To run the program, follow these steps:

```
go generate
go build
sudo ./map-exporter
```

You can then test trigger actions on eBPF map using:

```
sudo bpftool map
sudo bpftool map update id <MAP-ID> key 0 0 0 0 value 1 0 0 0
sudo bpftool map delete id <MAP-ID> key 0 0 0 0
sudo bpftool map lookup id <MAP-ID> key 0 0 0 0
```

## eBPF Iterators

eBPF Iterators are a powerful feature that allows developers to iterate over kernel data structures efficiently. 
They facilitate detailed inspection and analysis by enabling safe traversal of complex data structures, 
making it easier to collect metrics, debug, and perform various monitoring tasks within the kernel space.
