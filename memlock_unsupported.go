//go:build !linux

package main

func removeMemlock() error {
	return nil
}
