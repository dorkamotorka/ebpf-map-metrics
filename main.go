package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 sync sync.c

import (
	"log"
	"fmt"
	"net/http"
	"unsafe"

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
            Help: "Current number of items in eBPF maps, labeled by map ID",
        },
        []string{"map_id"},
    )
)

func getMapKeysLen(m *ebpf.Map) (int, error) {
    var keys [][]byte
    info, err := m.Info(); if err != nil {
	return -1, err
    }

    keySize := int(info.KeySize)
    valueSize := int(info.ValueSize)

    key := make([]byte, keySize)
    value := make([]byte, valueSize)
    it := m.Iterate()
    for it.Next(&key, &value) {
	// append key if value non-zero
	if isNonZero(value) {
		keys = append(keys, append([]byte(nil), key...))
	}
    }  

    return len(keys), nil
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
	if err := loadSyncObjects(&syncObjs, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/test/maps"}}); err != nil {
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

	mapsIDs := make(map[string]*ebpf.Map)
	mapsLengths := make(map[string]int)

	// Append all maps we track into the array so we can loop through it
	var maps []*ebpf.Map
	maps = append(maps, syncObjs.syncMaps.ArrayMap, syncObjs.syncMaps.HashMap, syncObjs.syncMaps.LruHashMap)
	for _, m := range maps {
		info, err := m.Info()
		if err != nil {
		    log.Fatalf("Failed to get map info: %v", err)
		}

		mapID, opt := info.ID()
		if !opt {
		    log.Printf("Map %s doesn't not support ID() call", info.Name)
		    continue
		}
		id := fmt.Sprintf("%d", mapID)
		mapsIDs[id] = m
		length, err := getMapKeysLen(m)
		if err != nil {
		    log.Fatalf("Failed to get keys for map %s: %v", id, err)
		}

		mapsLengths[id] = length
            	mapItemCountGauge.WithLabelValues(id).Set(float64(length))
	}

	// Print the number of keys for each map for debugging
	for name, l := range mapsLengths {
		fmt.Printf("Map %s has %d keys\n", name, l)
	}


	rd, err := ringbuf.NewReader(syncObjs.MapEvents)
	if err != nil {
		panic(err)
	}
	defer rd.Close()

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

		mapID := fmt.Sprintf("%d", Event.MapID)
		m := mapsIDs[mapID]
		
		// Since the metrics of all other maps (then the one loaded by this program) would be wrong, we skip them
		_, ok := mapsLengths[mapID]; if !ok {
			continue
		}

		length, err := getMapKeysLen(m); if err != nil {
			log.Printf("Failed to get length of the map %s", mapID)
			continue
		}
            	mapItemCountGauge.WithLabelValues(mapID).Set(float64(length))
	}
}
