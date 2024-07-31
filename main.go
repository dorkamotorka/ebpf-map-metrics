package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 sync sync.c

import (
	"log"
	"fmt"
	"net/http"
	"unsafe"
	"os"
    	"path/filepath"
	"bytes"
	"encoding/gob"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

    	"github.com/prometheus/client_golang/prometheus"
    	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Define Prometheus metrics
var (	   
    mapItemCountGauge = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "ebpf_map_item_count",
            Help: "Current number of items in eBPF maps, labeled by map name",
        },
        []string{"map_name"},
    )
)

func main() {
        reg := prometheus.NewRegistry()
    	reg.MustRegister(mapItemCountGauge)
    	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
 	// Start HTTP server for Prometheus metrics
    	http.Handle("/metrics", handler)
    	go func() {
        	log.Fatal(http.ListenAndServe(":2112", nil))
    	}()
    	log.Println("Prometheus metrics available at http://localhost:2112/metrics")

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	syncObjs := syncObjects{}
	if err := loadSyncObjects(&syncObjs, nil); err != nil {
		log.Fatal(err)
	}
	defer syncObjs.Close()

	hashMapUpdate, err := link.AttachTracing(link.TracingOptions{
		Program: syncObjs.syncPrograms.BpfProgKernHmapupdate,
	})
	if err != nil {
		log.Fatalf("opening htab_map_update_elem kprobe: %s", err)
	}
	defer hashMapUpdate.Close()

	hashMapDelete, err := link.AttachTracing(link.TracingOptions{
		Program: syncObjs.syncPrograms.BpfProgKernHmapdelete,
	})
	if err != nil {
		log.Fatalf("opening htab_map_delete_elem kprobe: %s", err)
	}
	defer hashMapDelete.Close()

	lruHashMapUpdate, err := link.AttachTracing(link.TracingOptions{
                Program: syncObjs.syncPrograms.BpfProgKernLruhmapupdate,
        })
        if err != nil {
                log.Fatalf("opening lru_htab_map_update_elem kprobe: %s", err)
        }
        defer lruHashMapUpdate.Close()

        lruHashMapDelete, err := link.AttachTracing(link.TracingOptions{
                Program: syncObjs.syncPrograms.BpfProgKernLruhmapdelete,
        })
        if err != nil {
                log.Fatalf("opening lru_htab_map_delete_elem kprobe: %s", err)
        }
        defer lruHashMapDelete.Close()

        arrayUpdate, err := link.AttachTracing(link.TracingOptions{
                Program: syncObjs.syncPrograms.BpfProgKernArraymapupdate,
        })
        if err != nil {
                log.Fatalf("opening array_map_update_elem kprobe: %s", err)
        }
        defer arrayUpdate.Close()

        arrayDelete, err := link.AttachTracing(link.TracingOptions{
                Program: syncObjs.syncPrograms.BpfProgKernArraymapdelete,
        })
        if err != nil {
                log.Fatalf("opening array_map_delete_elem kprobe: %s", err)
        }
        defer arrayDelete.Close()

	rd, err := ringbuf.NewReader(syncObjs.MapEvents)
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	// The idea is to count the elements of each PINNED map
	// Because after restart the metric values would be wrong
	// TODO: How to resolve the non-pinned maps 
	eBPFMaps, err := restorePinnedMaps(); if err != nil {
		log.Fatal("Failed to restore eBPF Pinned Maps: %s", err)
	}

	for {
		record, err := rd.Read()
		if err != nil {
			panic(err)
		}

		Event := (*MapData)(unsafe.Pointer(&record.RawSample[0]))
		log.Printf("Map ID: %d", Event.MapID)
		log.Printf("Name: %s", string(Event.Name[:]))
		log.Printf("PID: %d", Event.PID)
		log.Printf("Update Type: %s", Event.UpdateType.String())
		log.Printf("Key: %d", Event.Key)
		log.Printf("Key Size: %d", Event.KeySize)
		log.Printf("Value: %d", Event.Value)
		log.Printf("Value Size: %d", Event.ValueSize)
		log.Printf("===========================================")

		mapName := string(Event.Name[:])
		// Convert to byte array
		key, err := AnyTypeToBytes(Event.Key)
		if err != nil {
			log.Fatalf("Error encoding data: %v", err)
		}

        	// Update Prometheus metrics based on event type
        	switch Event.UpdateType.String() {
        	case "UPDATE":
			if !isInArray(eBPFMaps[mapName], key) {
				eBPFMaps[mapName] = append(eBPFMaps[mapName], key)
            			mapItemCountGauge.WithLabelValues(mapName).Inc()
			} else {
				log.Printf("Element %d already present in the %s map", Event.Key, mapName)
				continue
			}
        	case "DELETE":
			for i, v := range eBPFMaps[mapName] {
        			if compareBytes(v, key) {
					// Removes the i-th element from the array
            				eBPFMaps[mapName] = append(eBPFMaps[mapName][:i], eBPFMaps[mapName][i+1:]...)
            				mapItemCountGauge.WithLabelValues(mapName).Dec()
					continue
        			}
				log.Printf("Element %d not present in the %s map", Event.Key, mapName)
    			}
        	}
	}
}
