package main

import (
        "bytes"
	"encoding/binary"
)

const BPF_NAME_LEN = 16

// Order matters!
type MapUpdater int32
const (
	MAP_UPDATE MapUpdater = iota
	MAP_DELETE
)

const (
	UPDATE = "UPDATE"
	DELETE = "DELETE"
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

func uintToBytes(n uint32) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, n)
	if err != nil {
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
