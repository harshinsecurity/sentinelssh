package utils

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func ReadTargetsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening target file: %v", err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target == "" {
			continue // Skip empty lines
		}
		// Handle URLs with or without protocol and path
		if strings.Contains(target, "://") {
			parsedURL, err := url.Parse(target)
			if err == nil {
				target = parsedURL.Hostname()
			}
		} else {
			// Remove any path or query parameters
			target = strings.Split(target, "/")[0]
		}
		targets = append(targets, target)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading target file: %v", err)
	}

	return targets, nil
}
