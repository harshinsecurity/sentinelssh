package analyzer

import (
	"strings"
)

var (
	vulnerableVersions = []string{
		"SSH-2.0-OpenSSH_1", "SSH-2.0-OpenSSH_2", "SSH-2.0-OpenSSH_3",
		"SSH-2.0-OpenSSH_4.0", "SSH-2.0-OpenSSH_4.1", "SSH-2.0-OpenSSH_4.2",
		"SSH-2.0-OpenSSH_4.3", "SSH-2.0-OpenSSH_4.4", "SSH-2.0-OpenSSH_8.5",
		"SSH-2.0-OpenSSH_8.6", "SSH-2.0-OpenSSH_8.7", "SSH-2.0-OpenSSH_8.8",
		"SSH-2.0-OpenSSH_8.9", "SSH-2.0-OpenSSH_9.0", "SSH-2.0-OpenSSH_9.1",
		"SSH-2.0-OpenSSH_9.2", "SSH-2.0-OpenSSH_9.3", "SSH-2.0-OpenSSH_9.4",
		"SSH-2.0-OpenSSH_9.5", "SSH-2.0-OpenSSH_9.6", "SSH-2.0-OpenSSH_9.7",
	}
	excludedVersions = []string{
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		"SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu3.6",
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3",
		"SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6",
		"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
		"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
	}
)

func AnalyzeVersion(banner string) string {
	if !strings.HasPrefix(banner, "SSH-2.0-") {
		return "unknown"
	}
	for _, v := range vulnerableVersions {
		if strings.HasPrefix(banner, v) {
			for _, e := range excludedVersions {
				if banner == e {
					return "patched"
				}
			}
			return "vulnerable"
		}
	}
	return "secure"
}
