package macho

type CodeSignCommand struct {
	Cmd      uint32
	Cmdsize  uint32
	Dataoff  uint32
	Datasize uint32
}

type EncryptionInfoCommand struct {
	Cmd       uint32
	Cmdsize   uint32
	Cryptoff  uint32
	Cryptsize uint32
	Cryptid   uint32
}

type CodeSignSuperBlob struct {
	Magic  uint32
	Length uint32
	Count  uint32
}

type CSCodeDirectory struct {
	Magic         uint32
	Length        uint32
	Version       uint32
	Flags         uint32
	HashOffset    uint32
	IdentOffset   uint32
	NSpecialSlots uint32
	NCodeSlots    uint32
	CodeLimit     uint32
	HashSize      uint8  /* size of each hash in bytes */
	HashType      uint8  /* type of hash (cdHashType* constants) */
	Spare1        uint8  /* unused (must be zero) */
	PageSize      uint8  /* log2(page size in bytes); 0 => infinite */
	Spare2        uint32 /* unused (must be zero) */
	//char end_earliest[0];

	/* Version 0x20100 */
	ScatterOffset uint32 /* offset of optional scatter vector */
	//char end_withScatter[0];

	/* Version 0x20200 */
	TeamOffset uint32 /* offset of optional team identifier */
	//char end_withTeam[0];

	/* Version 0x20300 */
	Spare3      uint32 /* unused (must be zero) */
	CodeLimit64 uint64 /* limit to main image signature range, 64 bits */
	//char end_withCodeLimit64[0];

	/* Version 0x20400 */
	ExecSegBase  uint64 /* offset of executable segment */
	ExecSegLimit uint64 /* limit of executable segment */
	ExecSegFlags uint64 /* executable segment flags */
	//char end_withExecSeg[0];

	/* followed by dynamic content as located by offset fields above */
}

type MachHeader struct {
	Magic      uint32 /* mach magic number identifier */
	Cputype    int    /* cpu specifier */
	Cpusubtype int    /* machine specifier */
	Filetype   uint32 /* type of file */
	Ncmds      uint32 /* number of load commands */
	Sizeofcmds uint32 /* the size of all the load commands */
	Flags      uint32 /* flags */
}
