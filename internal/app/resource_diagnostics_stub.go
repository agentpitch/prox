//go:build !windows

package app

type resourceOSStats struct {
	PrivateBytes        uint64            `json:"private_bytes"`
	WorkingSetBytes     uint64            `json:"working_set_bytes"`
	PeakWorkingSetBytes uint64            `json:"peak_working_set_bytes"`
	PagefileBytes       uint64            `json:"pagefile_bytes"`
	PeakPagefileBytes   uint64            `json:"peak_pagefile_bytes"`
	PageFaultCount      uint32            `json:"page_fault_count"`
	HandleCount         uint32            `json:"handle_count"`
	GDIHandleCount      uint32            `json:"gdi_handle_count"`
	UserHandleCount     uint32            `json:"user_handle_count"`
	UserTimeMs          uint64            `json:"user_time_ms"`
	KernelTimeMs        uint64            `json:"kernel_time_ms"`
	ReadOperationCount  uint64            `json:"read_operation_count"`
	WriteOperationCount uint64            `json:"write_operation_count"`
	OtherOperationCount uint64            `json:"other_operation_count"`
	ReadTransferBytes   uint64            `json:"read_transfer_bytes"`
	WriteTransferBytes  uint64            `json:"write_transfer_bytes"`
	OtherTransferBytes  uint64            `json:"other_transfer_bytes"`
	HandleTypes         map[string]uint32 `json:"handle_types,omitempty"`
}

func readResourceOSStats(includeHandleTypes bool) (resourceOSStats, error) {
	return resourceOSStats{}, nil
}
