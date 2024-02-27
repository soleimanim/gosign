package macho

func Swap16(value uint16) uint16 {
	return (value>>8)&0x00ff |
		(value<<8)&0xff00
}

func Swap32(value uint32) uint32 {
	value = (value>>8)&0x00ff00ff |
		(value<<8)&0xff00ff00
	value = (value>>16)&0x0000ffff |
		(value<<16)&0xffff0000
	return value
}

func Swap64(value uint64) uint64 {
	value = (value&0x00000000ffffffff)<<32 | (value&0xffffffff00000000)>>32
	value = (value&0x0000ffff0000ffff)<<16 | (value&0xffff0000ffff0000)>>16
	value = (value&0x00ff00ff00ff00ff)<<8 | (value&0xff00ff00ff00ff00)>>8
	return value
}
