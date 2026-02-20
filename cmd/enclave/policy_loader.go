package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// EnclavePolicy defines the runtime policy for the Enclave VM.
type EnclavePolicy struct {
	Mounts []MountConfig `yaml:"mounts"`
}

// MountConfig defines a host directory to be mounted into the guest.
type MountConfig struct {
	HostPath  string `yaml:"host"`
	GuestPath string `yaml:"guest"`
	ReadOnly  bool   `yaml:"readonly"`
}

// LoadPolicy reads and parses the policy file.
func LoadPolicy(path string) (*EnclavePolicy, error) {
	if path == "" {
		return &EnclavePolicy{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy EnclavePolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	return &policy, nil
}
