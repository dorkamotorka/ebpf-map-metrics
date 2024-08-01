# ebpf-map-metrics

## Development Status

This project is currently under development.

**Note:** The tool only exposes metrics that were loaded by that same program. So it's not a generic standalone exporter and it requires for you to integrate it into you app. Also at its current state it only support keys of type **uint32**. To support arbitrary data type, some additional stuff needs to be added on top.


So far it supports metrics for:

- Hash eBPF Map
- Array eBPF Map
- Hash LRU eBPF Map

## How to Run

To run the program, follow these steps:

```
go generate
go build
sudo ./ebpf-map-metrics
```

On each host you can trigger actions on eBPF map using:

```
sudo bpftool map
sudo bpftool map update id <MAP-ID> key 0 0 0 0 value 1 0 0 0
sudo bpftool map delete id <MAP-ID> key 0 0 0 0
sudo bpftool map lookup id <MAP-ID> key 0 0 0 0
```

## Hook Points

It's kindy hacky how I found the attachment point, but I listed all the possible kprobe and searched for the `map` key word.

```
bpftrace -l 'kprobe:*' | grep map
```

Then I checked the Linux Kernel source code to find the input arguments to the function.

## Fentry vs. Fexit

We use fexit instead of fentry, because ret also tells us whether the operation was actually successful or not.
Unsuccessful operation is e.g. deleting a key that doesn't exists.
