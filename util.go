package main

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
