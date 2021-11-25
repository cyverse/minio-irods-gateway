package irods

import (
	"fmt"
	"io"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
)

// IRODSFileRW wraps iRODS FileHandle
type IRODSFileRW struct {
	fileHandle *irodsclient_fs.FileHandle
}

func NewIRODSFileRW(fh *irodsclient_fs.FileHandle) *IRODSFileRW {
	return &IRODSFileRW{
		fileHandle: fh,
	}
}

func (rw *IRODSFileRW) Close() error {
	err := rw.fileHandle.Close()
	rw.fileHandle = nil
	return err
}

func (rw *IRODSFileRW) ReadAt(p []byte, off int64) (int, error) {
	if rw.fileHandle == nil {
		return 0, fmt.Errorf("null File Handle")
	}

	eof := false
	if off+int64(len(p)) >= rw.fileHandle.Entry.Size {
		// eof
		eof = true
	}

	buff, err := rw.fileHandle.ReadAt(off, len(p))
	if err != nil {
		return 0, err
	}

	// copy
	copy(p, buff)

	if eof {
		return len(buff), io.EOF
	}
	return len(buff), nil
}

func (rw *IRODSFileRW) Write(p []byte) (int, error) {
	if rw.fileHandle == nil {
		return 0, fmt.Errorf("null File Handle")
	}

	err := rw.fileHandle.Write(p)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}
