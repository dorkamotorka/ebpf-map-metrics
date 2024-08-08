package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go count count.c

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	UPDATE_INTERVAL = 1 // sec
)

var (
	mapElemCountGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_map_curr_elem_count",
			Help: "Current number of elements in eBPF maps, labeled by map ID and name",
		},
		[]string{"id", "name"},
	)

	mapPressureGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_map_pressure",
			Help: "Current pressure of eBPF maps (currElements / maxElements), labeled by map ID and name",
		},
		[]string{"id", "name"},
	)
)

func main() {
	reg := prometheus.NewRegistry()
	reg.MustRegister(mapElemCountGauge)
	reg.MustRegister(mapPressureGauge)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	objs := countObjects{}
	if err := loadCountObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	// Attach the program to the Iterator hook.
	iterLink, err := link.AttachIter(link.IterOptions{
		Program: objs.DumpBpfMap,
	})
	if err != nil {
		log.Fatalf("Failed to attach eBPF program: %v", err)
	}
	defer iterLink.Close()
	log.Println("eBPF program attached successfully.")

	// Start HTTP server for Prometheus metrics
	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	http.Handle("/metrics", handler)
	go func() {
		log.Fatal(http.ListenAndServe(":2112", nil))
	}()
	log.Println("Prometheus HTTP server started on :2112")

	// Keep the program running.
	for {
		time.Sleep(UPDATE_INTERVAL * time.Second)
		reader, err := iterLink.Open()
		if err != nil {
			log.Fatalf("Failed to open BPF iterator: %v", err)
		}
		defer reader.Close()

		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			// Variables to store the parsed values
			var id int
			var name string
			var maxElements int
			var currElements int64

			// Parse the line
			line := scanner.Text()
			length, err := fmt.Sscanf(line, "%4d %s %10d %10d", &id, &name, &maxElements, &currElements)
			if err != nil || length != 4 {
				log.Fatal(err)
			}

			// Update the metrics
			idStr := fmt.Sprintf("%d", id)
			mapElemCountGauge.WithLabelValues(idStr, name).Set(float64(currElements))
			mapPressureGauge.WithLabelValues(idStr, name).Set(float64(currElements) / float64(maxElements))
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}
}
