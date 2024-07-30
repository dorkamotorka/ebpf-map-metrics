# ebpf-map-metrics

## Development Status

This project is currently under development.

**Note:** The tool only counts elements in the array that were added or removed *after* the program starts running. We are actively exploring solutions to improve this functionality.

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
