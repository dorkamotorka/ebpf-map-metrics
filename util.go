package main

import (
        "bytes"
        "encoding/gob"
	"os"
        "path/filepath"
	"github.com/cilium/ebpf"
)

const (
      BPF_NAME_LEN = 16
      
      // Path to BPF filesystem
      bpfFsPath = "/sys/fs/bpf"

      UPDATE = "UPDATE"
      DELETE = "DELETE"
)

// Order matters!
type MapUpdater int32
const (
	MAP_UPDATE MapUpdater = iota
	MAP_DELETE
)

type MapData struct {
    MapID     uint32
    Name      [BPF_NAME_LEN]byte
    UpdateType   MapUpdater
    PID       uint32
    KeySize   uint32
    ValueSize uint32
    Key       uint32
    Value     uint32
}

func (e MapUpdater) String() string {
	switch e {
	case MAP_UPDATE:
		return UPDATE
	case MAP_DELETE:
		return DELETE
	default:
		return "UNKNOWN"
	}
}

// AnyTypeToBytes converts a variable of any type to a byte array using gob encoding
func AnyTypeToBytes(data interface{}) ([]byte, error) {
        var buf bytes.Buffer
        enc := gob.NewEncoder(&buf)
        if err := enc.Encode(data); err != nil {
                return nil, err
        }
        return buf.Bytes(), nil
}

func compareBytes(a, b []byte) bool {
        if len(a) != len(b) {
                return false
        }

        // Check byte by byte if they match
        for i := range a {
                if a[i] != b[i] {
                        return false
                }
        }
        return true
}

// Function to check if an element is in an array
func isInArray(arr [][]byte, elem []byte) bool {
    for _, v := range arr {
        if compareBytes(v, elem) {
            return true
        }
    }
    return false
}

// isNonZero checks if all the bytes are non-zero
func isNonZero(value []byte) bool {
    for _, v := range value {
        if v != 0 {
            return true
        }
    }
    return false
}


func restorePinnedMaps() (map[string][][]byte, error) {
        eBPFMaps := make(map[string][][]byte)

        // Walk through the BPF filesystem and try to load each file as a pinned map
	err := filepath.Walk(bpfFsPath, func(path string, info os.FileInfo, err error) error {
                if err != nil {
                        return err
                }

                // Attempt to load the file as a pinned map
                if !info.IsDir() {
                        m, err := ebpf.LoadPinnedMap(path, nil)
                        if err == nil {
                                info, err := m.Info(); if err != nil {
                                        return err
                                }

                                keySize := int(info.KeySize)
                                valueSize := int(info.ValueSize)

                                key := make([]byte, keySize)
                                value := make([]byte, valueSize)
                                it := m.Iterate()
                                for it.Next(&key, &value) {
                                        // append key if value non-zero
                                        //
                                        if isNonZero(value) {
                                                eBPFMaps[info.Name] = append(eBPFMaps[info.Name], append([]byte(nil), key...))
                                                mapItemCountGauge.WithLabelValues(info.Name).Inc()
                                        }
                                }
                        }
                }

                return nil
        })

        if err != nil {
                return nil, err
        }
	return eBPFMaps, nil
}
