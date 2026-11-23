//go:build !unix && !windows

package portscan

// Platforms without dedicated errno tables fall back to StateError for socket
// level failures; timeouts and cancellation are still classified.
func isConnRefused(error) bool { return false }

func isUnreachable(error) bool { return false }
