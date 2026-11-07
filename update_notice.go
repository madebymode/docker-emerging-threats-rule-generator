//go:build native

package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
)

const noticeFile = "update-notices.json"

type releaseNotice struct {
	Installed string               `json:"installed"`
	Available string               `json:"available"`
	Sent      map[string]time.Time `json:"sent"`
}

func readReleaseNotice(root *os.Root) (releaseNotice, error) {
	var notice releaseNotice
	f, err := root.OpenFile(noticeFile, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		return notice, nil
	}
	if err != nil {
		return notice, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return notice, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return notice, fmt.Errorf("notification state must be a regular file of at most 64 KiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if err != nil {
		return notice, err
	}
	if len(data) > 64*1024 {
		return notice, fmt.Errorf("notification state exceeds 64 KiB")
	}
	err = json.Unmarshal(data, &notice)
	return notice, err
}

func writeReleaseNotice(root *os.Root, notice releaseNotice) error {
	data, err := json.Marshal(notice)
	if err != nil {
		return err
	}
	name := ".update-notices-" + rand.Text()
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(name)
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	return root.Rename(name, noticeFile)
}
