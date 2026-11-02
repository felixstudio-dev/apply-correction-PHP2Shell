package mitigation

import (
	"errors"
	"reflect"
)

type fileMetadata struct {
	UID    uint32            `json:"uid"`
	GID    uint32            `json:"gid"`
	Mode   uint32            `json:"mode"`
	Xattrs map[string][]byte `json:"xattrs"`
}

func requireMetadata(path string, expected *fileMetadata) error {
	actual, err := captureMetadata(path)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, expected) {
		return errors.New("configuration metadata changed or backup lacks metadata; manual review required")
	}
	return nil
}
