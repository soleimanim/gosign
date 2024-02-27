package macho

import (
	"bytes"
	"debug/macho"
	"fmt"
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
