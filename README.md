# eBPF Map Metrics Prometheus Exporter

This project exports eBPF Map Pressure and elements count as Prometheus metrics.

**NOTE**: Certain eBPF Maps are fixed-sized and don't maintain a counter of elements internally. For those the values of elements is equal to the max number of entries specified for that map.

## Development Status

This project is currently under development.

It requires `6.6+` Linux Kernel, due to `bpf_map_sum_elem_count` kfunc.

![Infra-9](https://github.com/user-attachments/assets/de0a70c1-1fbb-498c-b3de-80c1d1c0bf7b)

## eBPF Iterators

eBPF Iterators are a powerful feature that allows developers to iterate over kernel data structures efficiently. 
They facilitate detailed inspection and analysis by enabling safe traversal of complex data structures, 
making it easier to collect metrics, debug, and perform various monitoring tasks within the kernel space (and send it back to the user space).
