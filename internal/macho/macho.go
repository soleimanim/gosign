package macho

import (
	"debug/macho"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/soleimanim/gosign/internal/logger"
)

type MachOFile struct {
	logger   logger.Logger
	filePath string
	file     *os.File
	data     []byte
	archs    []MachOArch
}

func NewMachOFile(path string) MachOFile {
	return MachOFile{filePath: path, logger: logger.New()}
}

// Initialize macho file, Reading file data and extracting archs
//
// Returns:
//   - error	nil if init successfull
func (m *MachOFile) Init() error {
	err := m.open()
	if err != nil {
		m.logger.Errorln("could not open file, error: ", err)
		return err
	}

	magic := GetUInt32(m.data, 4, 0, false)

	m.logger.Debugf("initializing macho file with magic: %08x\n", magic)

	switch magic {
	case FAT_MAGIC, FAT_CIGAM:
		m.logger.Debugln("macho file is fat")
		archs, err := getArchsFromFatFile(*m)
		if err != nil {
			return err
		}

		m.archs = archs
	case MH_CIGAM, MH_CIGAM_64, MH_MAGIC, MH_MAGIC_64:
		m.logger.Debugln("macho file is not fat")
		arch := NewMachOArch(m.data, m.logger)
		err := arch.Init()
		if err != nil {
			return err
		}
		m.archs = []MachOArch{arch}
	default:
		return fmt.Errorf("unsupported magic number %08x", magic)
	}

	return nil
}

// open file and read data
//
// Returns:
//   - error 	nil in case of success
func (m *MachOFile) open() error {
	file, err := os.Open(m.filePath)
	if err != nil {
		return err
	}

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	data := make([]byte, stat.Size())
	length, err := io.ReadFull(file, data)

	if err != nil {
		return err
	}

	if int64(length) != stat.Size() {
		return errors.New("error reading file data")
	}

	m.file = file
	m.data = data

	return nil
}

// Read archs by size and offset from file
//
// Parameters:
//   - MachOFile
//
// Returns:
//   - MachOArch
//   - error 	nil in case of success
func getArchsFromFatFile(m MachOFile) ([]MachOArch, error) {
	archs := []MachOArch{}
	fat, err := macho.NewFatFile(m.file)
	if err != nil {
		return archs, err
	}

	m.logger.Debugln("Reading fat file archs, count:", len(fat.Arches))

	for i, arch := range fat.Arches {
		m.logger.Debugf("\t#%d offset: %d, size: %d\n", i, arch.Offset, arch.Size)

		data := m.data[arch.Offset : arch.Offset+arch.Size]
		arch := NewMachOArch(data, m.logger)
		err := arch.Init()
		if err != nil {
			return archs, err
		}
		archs = append(archs, arch)
	}

	return archs, nil
}
