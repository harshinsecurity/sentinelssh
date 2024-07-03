package models

type ScanResult struct {
	Target string
	IP     string
	Port   int
	Status string
	Banner string
}
