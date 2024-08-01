package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 sync sync.c

import (
	"log"
	"fmt"
	"net/http"
	"unsafe"
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

    	"github.com/prometheus/client_golang/prometheus"
    	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Define Prometheus metrics
// NOTE: Labelling by string is kinda tricky, so we do it with ID for now
// Pinned maps, retain the ID!
// If pinned map file deleted, it gets a new ID but the developer should be aware of that
var (	   
    mapItemCountGauge = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "ebpf_map_item_count",
            Help: "Current number of items in eBPF maps, labeled by map ID",
        },
        []string{"map_id"},
    )
)

func getMapKeys(m *ebpf.Map) ([][]byte, error) {
    var keys [][]byte
    info, err := m.Info(); if err != nil {
	return nil, err
    }

    mapID, opt := info.ID()
    if !opt {
       log.Printf("Map %s doesn't not support ID() call", info.Name)
       return nil, errors.New("doesn't support ID()")
    }
    mapName := fmt.Sprintf("%d", mapID)

    keySize := int(info.KeySize)
    valueSize := int(info.ValueSize)

    key := make([]byte, keySize)
    value := make([]byte, valueSize)
    it := m.Iterate()
    for it.Next(&key, &value) {
	// append key if value non-zero
	if isNonZero(value) {
		keys = append(keys, append([]byte(nil), key...))
		mapItemCountGauge.WithLabelValues(string(mapName)).Inc()
	}
    }  

    return keys, nil
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

	// Append all maps we track into the array so we can loop through it
	var maps []*ebpf.Map
	maps = append(maps, syncObjs.syncMaps.ArrayMap, syncObjs.syncMaps.HashMap, syncObjs.syncMaps.LruHashMap)

	mapsKeys := make(map[string][][]byte)
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
		mapName := fmt.Sprintf("%d", mapID)
		keys, err := getMapKeys(m)
		if err != nil {
		    log.Fatalf("Failed to get keys for map %s: %v", mapName, err)
		}

		mapsKeys[mapName] = keys
	}

	// Print the keys for each map for debugging
	for name, keys := range mapsKeys {
		fmt.Printf("Map %s has keys: %v\n", name, keys)
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

		mapName := fmt.Sprintf("%d", Event.MapID)
		// Convert to byte array
		// NOTE: only key of type uint is demonstrated
		// If the key is of different type it needs to be changed both in ring buffer event
		// As well as figure out a way to compare it to keys already stored in the map (retrieved from pinned map)
		key, err := uintToBytes(Event.Key)
		if err != nil {
			log.Fatalf("Error encoding data: %v", err)
		}

        	// Update Prometheus metrics based on event type
        	switch Event.UpdateType.String() {
        	case "UPDATE":
			if !isInArray(mapsKeys[mapName], key) {
				mapsKeys[mapName] = append(mapsKeys[mapName], key)
            			mapItemCountGauge.WithLabelValues(mapName).Inc()
			} else {
				log.Printf("Element %d already present in the %s map", Event.Key, mapName)
				continue
			}
        	case "DELETE":
			for i, v := range mapsKeys[mapName] {
        			if compareBytes(v, key) {
					// Removes the i-th element from the array
            				mapsKeys[mapName] = append(mapsKeys[mapName][:i], mapsKeys[mapName][i+1:]...)
            				mapItemCountGauge.WithLabelValues(mapName).Dec()
					continue
        			}
				log.Printf("Element %d not present in the %s map", Event.Key, mapName)
    			}
        	}
	}
}
