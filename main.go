package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 sync sync.c

import (
	"fmt"
	"log"
	"net/http"
	"unsafe"

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
            Help: "Current number of items in eBPF maps, labeled by map ID",
        },
        []string{"map_id"},
    )
)

// Function to check if an element is in an array
func isInArray(arr []uint32, elem uint32) bool {
    for _, v := range arr {
        if v == elem {
            return true
        }
    }
    return false
}


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

	eBPFMaps := make(map[string][]uint32)
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

                // Convert map ID to string for use as a label
        	mapIDStr := fmt.Sprintf("%d", Event.MapID)

        	// Update Prometheus metrics based on event type
        	switch Event.UpdateType.String() {
        	case "UPDATE":
			if !isInArray(eBPFMaps[mapIDStr], Event.Key) {
				eBPFMaps[mapIDStr] = append(eBPFMaps[mapIDStr], Event.Key)
            			mapItemCountGauge.WithLabelValues(mapIDStr).Inc()
			} else {
				log.Println("Element %d already present in the map", Event.Key)
				continue
			}
        	case "DELETE":
			for i, v := range eBPFMaps[mapIDStr] {
        			if v == Event.Key {
            				eBPFMaps[mapIDStr] = append(eBPFMaps[mapIDStr][:i], eBPFMaps[mapIDStr][i+1:]...)
            				mapItemCountGauge.WithLabelValues(mapIDStr).Dec()
					continue
        			}
    			}
			log.Println("Element %d not present in the map", Event.Key)
        	}
	}
}
