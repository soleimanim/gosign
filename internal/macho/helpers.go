package macho

import "encoding/binary"

func GetUInt32(data []byte, size int, offset int, bigEndian bool) uint32 {
	if bigEndian {
		return binary.BigEndian.Uint32(data[offset : offset+size])
	} else {
		return binary.LittleEndian.Uint32(data[offset : offset+size])
	}
}
