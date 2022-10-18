module github.com/opencontainers/runc

go 1.16

require (
	github.com/checkpoint-restore/go-criu/v5 v5.3.0
	github.com/cilium/ebpf v0.7.0
	github.com/containerd/console v1.0.3
	github.com/coreos/go-systemd/v22 v22.3.2
	github.com/cyphar/filepath-securejoin v0.2.3
	github.com/docker/go-units v0.4.0
	github.com/godbus/dbus/v5 v5.0.6
	github.com/moby/sys/mountinfo v0.5.0
	github.com/mrunalp/fileutils v0.5.0
	github.com/opencontainers/runtime-spec v1.0.3-0.20220718201635-a8106e99982b
	github.com/opencontainers/selinux v1.10.0
	github.com/seccomp/libseccomp-golang v0.9.2-0.20220502022130-f33da4d89646
	github.com/sirupsen/logrus v1.8.1
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635
	// NOTE: urfave/cli must be <= v1.22.1 due to a regression: https://github.com/urfave/cli/issues/1092
	github.com/urfave/cli v1.22.1
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b
	golang.org/x/sys v0.0.0-20211116061358-0a5406a5449c
	google.golang.org/protobuf v1.27.1
)
