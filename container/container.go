// Package container provides tools for introspecting containers.
package container

import (
	"errors"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/syndtr/gocapability/capability"
)

const (
	// RuntimeDocker is the docker runtime.
	RuntimeDocker = "docker"
	// RuntimeRkt is the rkt runtime.
	RuntimeRkt = "rkt"
	// RuntimeNspawn is the systemd-nspawn runtime.
	RuntimeNspawn = "systemd-nspawn"
	// RuntimeLXC is the lxc runtime.
	RuntimeLXC = "lxc"
	// RuntimeLXCLibvirt is the lxc-libvirt runtime.
	RuntimeLXCLibvirt = "lxc-libvirt"
	// RuntimeOpenVZ is the openvz runtime.
	RuntimeOpenVZ = "openvz"

	uint32Max = 4294967295
)

var (
	// ErrContainerRuntimeNotFound describes when a container runtime could not be found.
	ErrContainerRuntimeNotFound = errors.New("container runtime could not be found")

	runtimes = []string{RuntimeDocker, RuntimeRkt, RuntimeNspawn, RuntimeLXC, RuntimeLXCLibvirt, RuntimeOpenVZ}
)

// DetectRuntime returns the container runtime the process is running in.
func DetectRuntime() (string, error) {
	// read the cgroups file
	cgroups := readFile("/proc/self/cgroup")
	if len(cgroups) > 0 {
		for _, runtime := range runtimes {
			if strings.Contains(cgroups, runtime) {
				return runtime, nil
			}
		}
	}

	// /proc/vz exists in container and outside of the container, /proc/bc only outside of the container.
	if fileExists("/proc/vz") && !fileExists("/proc/bc") {
		return RuntimeOpenVZ, nil
	}

	// If we are PID 1 we can check the container environment variable.
	if os.Getpid() == 1 {
		ctrenv := os.Getenv("container")
		if ctrenv != "" {
			for _, runtime := range runtimes {
				if ctrenv == runtime {
					return runtime, nil
				}
			}
		}
	}

	// PID 1 might have dropped this information into a file in /run.
	// Read from /run/systemd/container since it is better than accessing /proc/1/environ,
	// which needs CAP_SYS_PTRACE
	f := readFile("/run/systemd/container")
	if len(f) > 0 {
		for _, runtime := range runtimes {
			if f == runtime {
				return runtime, nil
			}
		}
	}

	return "not-found", ErrContainerRuntimeNotFound
}

// HasPIDNamespace determines if the container is using a PID namespace or the host PID namespace.
// Since /proc/1/sched shows the host's PID for what we see as PID 1, if the PID shown
// there is not 1, we know we are in a PID namespace.
func HasPIDNamespace() bool {
	f := readFile("/proc/1/sched")
	if len(f) > 0 {
		if !strings.Contains(f, " (1") {
			return true
		}
	}

	return false
}

// AppArmorProfile determines the apparmor profile for a container.
func AppArmorProfile() string {
	f := readFile("/proc/self/attr/current")
	if f == "" {
		return "none"
	}
	return f
}

// UserMapping holds the values for a {uid,gid}_map.
type UserMapping struct {
	ContainerID int64
	HostID      int64
	Range       int64
}

// UserNamespace determines if the container is running in a UserNamespace and returns the mappings if so.
func UserNamespace() (bool, []UserMapping) {
	var err error

	f := readFile("/proc/self/uid_map")
	if len(f) < 0 {
		// user namespace is uninitialized
		return true, nil
	}

	parts := strings.Split(f, " ")
	parts = deleteEmpty(parts)
	if len(parts) < 3 {
		return false, nil
	}

	mappings := []UserMapping{}
	for i := 0; i < len(parts); i += 3 {
		nsu, hu, r := parts[i], parts[i+1], parts[i+2]
		mapping := UserMapping{}

		mapping.ContainerID, err = strconv.ParseInt(nsu, 10, 0)
		if err != nil {
			return false, nil
		}
		mapping.HostID, err = strconv.ParseInt(hu, 10, 0)
		if err != nil {
			return false, nil
		}
		mapping.Range, err = strconv.ParseInt(r, 10, 0)
		if err != nil {
			return false, nil
		}

		if mapping.ContainerID == 0 && mapping.HostID == 0 && mapping.Range == uint32Max {
			return false, nil
		}

		mappings = append(mappings, mapping)
	}

	return true, mappings
}

// Capabilities returns the allowed capabilities in the container.
func Capabilities() (map[string][]string, error) {
	allCaps := capability.List()

	caps, err := capability.NewPid(0)
	if err != nil {
		return nil, err
	}

	allowedCaps := map[string][]string{}
	allowedCaps["EFFECTIVE | PERMITTED | INHERITABLE"] = []string{}
	allowedCaps["BOUNDING"] = []string{}
	allowedCaps["AMBIENT"] = []string{}

	for _, cap := range allCaps {
		if caps.Get(capability.CAPS, cap) {
			allowedCaps["EFFECTIVE | PERMITTED | INHERITABLE"] = append(allowedCaps["EFFECTIVE | PERMITTED | INHERITABLE"], cap.String())
		}
		if caps.Get(capability.BOUNDING, cap) {
			allowedCaps["BOUNDING"] = append(allowedCaps["BOUNDING"], cap.String())
		}
		if caps.Get(capability.AMBIENT, cap) {
			allowedCaps["AMBIENT"] = append(allowedCaps["AMBIENT"], cap.String())
		}
	}

	return allowedCaps, nil
}

func fileExists(file string) bool {
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		return true
	}
	return false
}

func readFile(file string) string {
	if !fileExists(file) {
		return ""
	}

	b, err := ioutil.ReadFile(file)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func deleteEmpty(s []string) []string {
	var r []string
	for _, str := range s {
		if strings.TrimSpace(str) != "" {
			r = append(r, str)
		}
	}
	return r
}
