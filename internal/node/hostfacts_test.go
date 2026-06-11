package node

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeHostFS points the collector's file probes at a temp directory and
// returns helpers to populate it.
func fakeHostFS(t *testing.T) (writeDMI func(name, value string), writeOSRelease func(string), setCgroup func(string)) {
	t.Helper()
	dir := t.TempDir()
	origDMI, origCgroup, origDocker, origRelease := dmiRoot, procOneCgroup, dockerEnvPath, osReleasePath
	dmiRoot = filepath.Join(dir, "dmi")
	procOneCgroup = filepath.Join(dir, "cgroup")
	dockerEnvPath = filepath.Join(dir, "dockerenv")
	osReleasePath = filepath.Join(dir, "os-release")
	if err := os.MkdirAll(dmiRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		dmiRoot, procOneCgroup, dockerEnvPath, osReleasePath = origDMI, origCgroup, origDocker, origRelease
	})
	return func(name, value string) {
			if err := os.WriteFile(filepath.Join(dmiRoot, name), []byte(value+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, func(content string) {
			if err := os.WriteFile(osReleasePath, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}, func(content string) {
			if err := os.WriteFile(procOneCgroup, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
}

func TestHostFactsLinuxLaptop(t *testing.T) {
	writeDMI, writeOSRelease, _ := fakeHostFS(t)
	writeDMI("sys_vendor", "LENOVO")
	writeDMI("product_name", "21F8002JUS")
	writeDMI("chassis_type", "10")
	writeOSRelease("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.2 LTS\"\n")

	h := &SnapshotHost{Machine: "unknown", Virtualization: "unknown"}
	collectLinux(h)
	if h.Machine != "laptop" || h.Virtualization != "physical" || h.CloudProvider != "" {
		t.Fatalf("laptop facts: %+v", h)
	}
	if h.OSName != "Ubuntu 24.04.2 LTS" {
		t.Fatalf("os name: %q", h.OSName)
	}
}

func TestHostFactsLinuxCloudVM(t *testing.T) {
	writeDMI, _, _ := fakeHostFS(t)
	writeDMI("sys_vendor", "Amazon EC2")
	writeDMI("product_name", "t3.large")

	h := &SnapshotHost{Machine: "unknown", Virtualization: "unknown"}
	collectLinux(h)
	if h.Virtualization != "vm" || h.CloudProvider != "aws" || h.Machine != "server" {
		t.Fatalf("cloud VM facts: %+v", h)
	}
}

func TestHostFactsLinuxContainer(t *testing.T) {
	writeDMI, _, setCgroup := fakeHostFS(t)
	// Container detection wins even when DMI looks like a VM
	// underneath (a container on a cloud VM is "a container").
	writeDMI("sys_vendor", "Google")
	writeDMI("product_name", "Google Compute Engine")
	setCgroup("0::/kubepods/besteffort/pod1234/abcd\n")

	h := &SnapshotHost{Machine: "unknown", Virtualization: "unknown"}
	collectLinux(h)
	if h.Virtualization != "container" {
		t.Fatalf("container facts: %+v", h)
	}
	if h.CloudProvider != "gcp" {
		t.Fatalf("cloud through container: %+v", h)
	}
}

func TestHostFactsAzureAssetTag(t *testing.T) {
	writeDMI, _, _ := fakeHostFS(t)
	writeDMI("sys_vendor", "Microsoft Corporation")
	writeDMI("product_name", "Virtual Machine")
	writeDMI("chassis_asset_tag", "7783-7084-3265-9085-8269-3286-77")

	h := &SnapshotHost{Machine: "unknown", Virtualization: "unknown"}
	collectLinux(h)
	if h.Virtualization != "vm" || h.CloudProvider != "azure" {
		t.Fatalf("azure facts: %+v", h)
	}
}

// The host block never carries identifying data and never fails: with
// nothing readable, every field degrades to unknown/empty, and the
// closed vocabularies hold.
func TestHostFactsDegradesClosed(t *testing.T) {
	fakeHostFS(t) // empty fake fs

	h := &SnapshotHost{Machine: "unknown", Virtualization: "unknown"}
	collectLinux(h)
	if h.Machine != "unknown" || h.Virtualization != "unknown" || h.CloudProvider != "" {
		t.Fatalf("degraded facts: %+v", h)
	}
	if h.OSName != "Linux" {
		t.Fatalf("degraded os name: %q", h.OSName)
	}

	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"hostname", "user", "home", "ip"} {
		if jsonHasKey(t, raw, forbidden) {
			t.Fatalf("host block must not carry %q", forbidden)
		}
	}
}

func jsonHasKey(t *testing.T, raw []byte, key string) bool {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	_, ok := m[key]
	return ok
}

// Snapshots carry the host block, and a snapshot WITHOUT the block
// (as every pre-host node emits) still round-trips — the additive
// contract that keeps old envelopes verifying.
func TestSnapshotHostBlockAdditive(t *testing.T) {
	snap := Snapshot{SchemaVersion: SchemaSnapshot, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if jsonHasKey(t, raw, "host") {
		t.Fatal("absent host block must not serialize")
	}

	snap.Host = &SnapshotHost{OSName: "macOS 15.5", Machine: "laptop", Virtualization: "physical"}
	raw, err = json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var back Snapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Host == nil || back.Host.Machine != "laptop" {
		t.Fatalf("host block round-trip: %+v", back.Host)
	}
}

// Vendor strings that merely contain a cloud company name must not
// read as cloud: a Surface, a Chromebook and an on-prem Hyper-V guest
// are not cloud instances.
func TestHostFactsNotCloud(t *testing.T) {
	cases := []struct{ vendor, product, assetTag string }{
		{"Microsoft Corporation", "Surface Pro 9", ""},   // physical Surface
		{"Microsoft Corporation", "Virtual Machine", ""}, // on-prem Hyper-V
		{"Google", "Lazor", ""},                          // Chromebook
	}
	for _, c := range cases {
		writeDMI, _, _ := fakeHostFS(t)
		writeDMI("sys_vendor", c.vendor)
		writeDMI("product_name", c.product)
		if c.assetTag != "" {
			writeDMI("chassis_asset_tag", c.assetTag)
		}
		h := &SnapshotHost{Machine: "unknown", Virtualization: "unknown"}
		collectLinux(h)
		if h.CloudProvider != "" {
			t.Fatalf("%s/%s misread as cloud %q", c.vendor, c.product, h.CloudProvider)
		}
	}
}
