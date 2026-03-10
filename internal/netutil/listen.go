package netutil

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"
)

// ListenAutoPort tries the configured port; if busy, scans up to 10 higher ports.
func ListenAutoPort(bind string, port int, logger *slog.Logger) (net.Listener, int, error) {
	addr := fmt.Sprintf("%s:%d", bind, port)
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		// When port is 0, the OS assigns a random port -- return the actual port.
		actual := ln.Addr().(*net.TCPAddr).Port
		return ln, actual, nil
	}

	// Check if the error is "address already in use"
	if !errors.Is(err, syscall.EADDRINUSE) && !IsAddrInUse(err) {
		return nil, 0, err
	}

	logger.Warn("port in use, searching for available port", "port", port)
	for offset := 1; offset <= 10; offset++ {
		tryPort := port + offset
		addr = fmt.Sprintf("%s:%d", bind, tryPort)
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			logger.Info("using alternative port", "original", port, "actual", tryPort)
			return ln, tryPort, nil
		}
	}
	return nil, 0, fmt.Errorf("port %d and next 10 ports are all in use", port)
}

// IsAddrInUse returns true if the error indicates "address already in use".
func IsAddrInUse(err error) bool {
	return err != nil && (errors.Is(err, syscall.EADDRINUSE) ||
		func() bool {
			var opErr *net.OpError
			if errors.As(err, &opErr) {
				return errors.Is(opErr.Err, syscall.EADDRINUSE)
			}
			return false
		}())
}
