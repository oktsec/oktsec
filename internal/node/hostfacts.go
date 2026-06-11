package node

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Host inventory: non-identifying facts about WHERE this node runs, so
// an operator can tell a laptop from a server, a VM from bare metal,
// and an office machine from a cloud instance. Everything here is
// best-effort and closed-vocabulary — collection must never fail a
// snapshot, and the block carries no hostnames, usernames, IPs or
// filesystem paths (the envelope contract promises that).

// SnapshotHost is the additive host-environment block on
// node_snapshot.v1. Pointer + omitempty on the Snapshot struct keeps
// previously signed envelopes verifying unchanged (the policy-block
// precedent).
type SnapshotHost struct {
	// OSName is the human OS name and version ("macOS 15.5",
	// "Ubuntu 24.04.2 LTS", "Windows"), best-effort; "" when unknown.
	OSName string `json:"os_name,omitempty"`
	// Machine is the closed-set physical form factor:
	// "laptop" | "desktop" | "server" | "unknown".
	Machine string `json:"machine"`
	// Virtualization is the closed-set runtime substrate:
	// "physical" | "vm" | "container" | "unknown".
	Virtualization string `json:"virtualization"`
	// CloudProvider is the detected IaaS vendor when the substrate is
	// a cloud instance: "aws" | "gcp" | "azure" | ""; detection is
	// DMI-based (no metadata-endpoint calls).
	CloudProvider string `json:"cloud_provider,omitempty"`
}

// dmiRoot is the sysfs DMI directory, a var for tests.
var dmiRoot = "/sys/class/dmi/id"

// procOneCgroup is PID 1's cgroup file, a var for tests.
var procOneCgroup = "/proc/1/cgroup"

// dockerEnvPath marks a Docker container filesystem, a var for tests.
var dockerEnvPath = "/.dockerenv"

// osReleasePath is the standard Linux OS identification file, a var
// for tests.
var osReleasePath = "/etc/os-release"

// CollectHostFacts gathers the host block. It never returns an error:
// anything it cannot determine degrades to "unknown"/"".
func CollectHostFacts() *SnapshotHost {
	h := &SnapshotHost{Machine: "unknown", Virtualization: "unknown"}
	switch runtime.GOOS {
	case "linux":
		collectLinux(h)
	case "darwin":
		collectDarwin(h)
	case "windows":
		h.OSName = "Windows"
	}
	return h
}

func collectLinux(h *SnapshotHost) {
	h.OSName = linuxOSName()

	// Container beats VM: a container on a cloud VM is still, from the
	// operator's point of view, "running in a container".
	if inContainer() {
		h.Virtualization = "container"
	} else if vendor, product := dmiField("sys_vendor"), dmiField("product_name"); isVirtualMachine(vendor, product) {
		h.Virtualization = "vm"
	} else if vendor != "" || product != "" {
		h.Virtualization = "physical"
	}

	h.CloudProvider = cloudFromDMI(dmiField("sys_vendor"), dmiField("product_name"), dmiField("chassis_asset_tag"))

	switch chassis := strings.TrimSpace(dmiField("chassis_type")); chassis {
	case "8", "9", "10", "14", "31": // portable, laptop, notebook, sub-notebook, convertible
		h.Machine = "laptop"
	case "3", "4", "5", "6", "7", "13", "15", "16", "35": // desktop family
		h.Machine = "desktop"
	case "17", "23", "25", "28", "29": // server family (incl. blade, rack)
		h.Machine = "server"
	default:
		if h.Virtualization == "vm" || h.Virtualization == "container" || h.CloudProvider != "" {
			// Virtual substrates have no meaningful chassis; calling
			// them servers matches how operators read them.
			h.Machine = "server"
		}
	}
}

func collectDarwin(h *SnapshotHost) {
	if v := execLine("sw_vers", "-productVersion"); v != "" {
		h.OSName = "macOS " + v
	} else {
		h.OSName = "macOS"
	}
	model := execLine("sysctl", "-n", "hw.model")
	switch {
	case strings.Contains(model, "Book"):
		h.Machine = "laptop"
		h.Virtualization = "physical"
	case strings.Contains(model, "VirtualMac") || strings.Contains(model, "Virtual"):
		h.Machine = "server"
		h.Virtualization = "vm"
	case model != "":
		h.Machine = "desktop"
		h.Virtualization = "physical"
	}
}

// linuxOSName reads PRETTY_NAME from os-release ("Ubuntu 24.04.2 LTS").
func linuxOSName() string {
	raw, err := os.ReadFile(osReleasePath)
	if err != nil {
		return "Linux"
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return "Linux"
}

func inContainer() bool {
	if _, err := os.Stat(dockerEnvPath); err == nil {
		return true
	}
	raw, err := os.ReadFile(procOneCgroup)
	if err != nil {
		return false
	}
	s := string(raw)
	return strings.Contains(s, "docker") || strings.Contains(s, "kubepods") ||
		strings.Contains(s, "containerd") || strings.Contains(s, "lxc")
}

func isVirtualMachine(vendor, product string) bool {
	v := strings.ToLower(vendor + " " + product)
	for _, marker := range []string{"vmware", "virtualbox", "kvm", "qemu", "xen", "hyper-v", "virtual machine", "parallels", "bochs", "bhyve", "amazon ec2", "google compute engine"} {
		if strings.Contains(v, marker) {
			return true
		}
	}
	return false
}

func cloudFromDMI(vendor, product, assetTag string) string {
	v := strings.ToLower(vendor + " " + product + " " + assetTag)
	switch {
	case strings.Contains(v, "amazon") || strings.Contains(v, "ec2"):
		return "aws"
	case strings.Contains(v, "google"):
		return "gcp"
	case strings.Contains(v, "microsoft") || strings.Contains(v, "7783-7084-3265-9085-8269-3286-77"): // Azure chassis asset tag
		return "azure"
	}
	return ""
}

func dmiField(name string) string {
	raw, err := os.ReadFile(dmiRoot + "/" + name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func execLine(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
