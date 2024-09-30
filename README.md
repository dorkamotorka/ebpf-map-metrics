# eBPF Map Metrics Prometheus Exporter

## Development Status

This project is currently under development.

It requires `6.6+` Linux Kernel, due to `bpf_map_sum_elem_count` kfunc.

![Infra-9](https://github.com/user-attachments/assets/de0a70c1-1fbb-498c-b3de-80c1d1c0bf7b)

## How to Run

To run the program, follow these steps:

- First build and run the docker container with all the dependencies:
```
docker buildx create --name mybuilder --bootstrap --use
docker buildx build --push --platform linux/arm64,linux/amd64 --tag dorkamotorka/ubuntu-ebpf -f Dockerfile .
docker run --rm -it -v ~/ebpf-map-metrics/src:/ebpf-map-metrics --privileged -h test --name test --env TERM=xterm-color dorkamotorka/ubuntu-ebpf
```

- Exec into the container:
```
cd ebpf-map-metrics
go generate
go build
sudo ./map-exporter
```

- You can then test trigger actions on eBPF map using:

```
sudo bpftool map
sudo bpftool map update id <MAP-ID> key 0 0 0 0 value 1 0 0 0
sudo bpftool map delete id <MAP-ID> key 0 0 0 0
sudo bpftool map lookup id <MAP-ID> key 0 0 0 0
```

## eBPF Iterators

eBPF Iterators are a powerful feature that allows developers to iterate over kernel data structures efficiently. 
They facilitate detailed inspection and analysis by enabling safe traversal of complex data structures, 
making it easier to collect metrics, debug, and perform various monitoring tasks within the kernel space (and send it back to the user space).
