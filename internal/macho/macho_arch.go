package macho

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"strconv"
	"unsafe"

	"github.com/soleimanim/gosign/internal/logger"
)

type MachOArch struct {
	data []byte
	file *macho.File

	logger                logger.Logger
	codeSignCommand       CodeSignCommand
	encryptionIncoCommand EncryptionInfoCommand
	codeSignSuperBlob     CodeSignSuperBlob

	is64bit               bool
	isBigEndian           bool
	codeSignLength        uint32
	encrypted             bool
	embeddedInfoPlist     string
	loadCommandsFreeSpace uint32

	linkEditSegment *macho.Section
}

func NewMachOArch(data []byte, logger logger.Logger) MachOArch {
	return MachOArch{data: data, logger: logger}
}

func (m *MachOArch) Init() error {
	magic := GetUInt32(m.data, 4, 0, false)
	m.logger.Debugf("initializing arch with maginc %08x\n", magic)

	if magic != MH_CIGAM && magic != MH_CIGAM_64 && magic != MH_MAGIC && magic != MH_MAGIC_64 {
		return fmt.Errorf("unsupported arch  with magic number: 0x%08x", magic)
	}

	m.is64bit = magic == MH_CIGAM_64 || magic == MH_MAGIC_64
	m.isBigEndian = magic == MH_CIGAM || magic == MH_CIGAM_64

	reader := bytes.NewReader(m.data)
	file, err := macho.NewFile(reader)
	if err != nil {
		return err
	}

	m.file = file

	machHeader := *(*MachHeader)(unsafe.Pointer(&m.data[0]))
	headerSize := uint32(unsafe.Sizeof(machHeader))
	if m.is64bit {
		headerSize += 4
	}

	m.logger.Debugln("Reading arch sections")
	for _, section := range file.Sections {
		switch {
		case section.Name == "__text":
			sizeOfCommands := machHeader.Sizeofcmds
			if m.isBigEndian {
				sizeOfCommands = Swap32(sizeOfCommands)
			}
			if section.Offset > sizeOfCommands+headerSize {
				m.loadCommandsFreeSpace = section.Offset - sizeOfCommands - headerSize
			}
		case section.Name == "__info_plist":
			infoData := m.data[section.Offset : uint64(section.Offset)+section.Size]
			m.embeddedInfoPlist = string(infoData)
		case section.Seg == "__LINKEDIT":
			m.linkEditSegment = section
		}
	}

	for _, lc := range m.file.Loads {
		lcData := lc.Raw()
		code := GetUInt32(lcData, 4, 0, m.isBigEndian)
		switch code {
		case LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64:
			m.logger.Debugln("reading encryption data")
			encryptionInfo := *(*EncryptionInfoCommand)(unsafe.Pointer(&lcData[0]))
			m.encryptionIncoCommand = encryptionInfo
			if m.isBigEndian {
				m.encrypted = Swap32(encryptionInfo.Cryptid) >= 1
			} else {
				m.encrypted = encryptionInfo.Cryptid >= 1
			}
		case LC_CODE_SIGNATURE:
			m.logger.Debugln("reading code signature")
			cmdDataVal := *(*CodeSignCommand)(unsafe.Pointer(&lcData[0]))
			m.codeSignCommand = cmdDataVal

			var dataOffset uint32
			if m.isBigEndian {
				dataOffset = Swap32(cmdDataVal.Dataoff)
			} else {
				dataOffset = cmdDataVal.Dataoff
			}

			blob := *(*CodeSignSuperBlob)(unsafe.Pointer(&m.data[dataOffset]))
			if Swap32(blob.Magic) == CSMAGIC_EMBEDDED_SIGNATURE {
				m.codeSignLength = Swap32(blob.Length)
			} else {
				m.codeSignLength = blob.Length
			}

			m.codeSignSuperBlob = blob
		}
	}

	return nil
}

func (m MachOArch) Info() {
	var platform string
	if m.is64bit {
		platform = "64"
	} else {
		platform = "32"
	}

	m.logger.Printf("\n\n Macho Arch Info:\n")
	m.logger.Println("\tFile Type: \t\t", m.file.FileHeader.Type)
	m.logger.Printf("\tTotal Size: \t\t%d (%.2f MB)\n", len(m.data), float64(len(m.data))/1024.0/1024.0)
	m.logger.Println("\tPlatform: \t\t", platform)
	m.logger.Println("\tCPU Arch: \t\t", m.file.Cpu.String())
	m.logger.Printf("\tCPU Type: \t\t%08x\n", int(m.file.FileHeader.Cpu))
	m.logger.Printf("\tSub CPU Type: \t\t%08x\n", int(m.file.FileHeader.SubCpu))
	m.logger.Printf("\tByte Order: \t\t%s\n", m.file.ByteOrder)
	m.logger.Printf("\tEncrypted: \t\t%s\n", strconv.FormatBool(m.encrypted))
	m.logger.Printf("\tCommands Count: \t\t%d\n", m.file.Ncmd)
	m.logger.Printf(
		"\tCode Length: \t\t%d (%.2f MB)\n",
		m.codeSignCommand.Dataoff,
		float64(m.codeSignCommand.Dataoff)/1024.0/1024.0,
	)
	m.logger.Printf("\tSign Length: \t\t%d (%.2f MB)\n", m.codeSignLength, float64(m.codeSignLength)/1024.0/1024.0)
	m.logger.Printf(
		"\tSpare Length: \t\t%d (%.2f MB)\n",
		uint32(len(m.data))-m.codeSignLength-m.codeSignCommand.Dataoff,
		float64(uint32(len(m.data))-m.codeSignLength-m.codeSignCommand.Dataoff)/1024.0/1024.0,
	)

	var dylibs []macho.Load
	var weakDylibLoads []macho.Load

	for _, lc := range m.file.Loads {
		lcData := lc.Raw()
		lcCode := GetUInt32(lcData, 4, 0, false)
		switch lcCode {
		case LC_VERSION_MIN_IPHONEOS:
			var ver uint32
			ver = binary.LittleEndian.Uint32(lcData[8:12])
			m.logger.Printf("\tMinimum Iphone Version: \t\t%08x\n", ver)
		case LC_RPATH:
			rpath := lc.(*macho.Rpath)
			m.logger.Printf("\tLC_RPATH: \t\t%s\n", rpath.Path)
		case LC_LOAD_WEAK_DYLIB:
			weakDylibLoads = append(weakDylibLoads, lc)
		case LC_LOAD_DYLIB:
			dylibs = append(dylibs, lc)
		}
	}

	if len(dylibs) > 0 {
		m.logger.Printf("\n\tLC_LOAD_DYLIB:\n")

		for _, d := range dylibs {
			dylib := d.(*macho.Dylib)
			m.logger.Printf("\t\t%s\n", dylib.Name)
		}
	}

	if len(weakDylibLoads) > 0 {
		m.logger.Printf("\n\tLC_LOAD_WEAK_DYLIB:\n")

		for _, lc := range weakDylibLoads {
			lcData := lc.Raw()
			dylib := *(*macho.DylibCmd)(unsafe.Pointer(&lcData[0]))
			m.logger.Printf("\t\t%s (weak)\n", string(lcData[dylib.Name:]))
		}
	}

	if m.embeddedInfoPlist != "" {
		m.logger.Printf("\n\tEmbedded info plist:\n")
		m.logger.Println(m.embeddedInfoPlist)
	}

	// TODO: print code signature info
}
