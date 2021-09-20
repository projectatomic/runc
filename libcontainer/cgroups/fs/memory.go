// +build linux

package fs

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fscommon"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const (
	numaNodeSymbol            = "N"
	numaStatColumnSeparator   = " "
	numaStatKeyValueSeparator = "="
	numaStatMaxColumns        = math.MaxUint8 + 1
	numaStatValueIndex        = 1
	numaStatTypeIndex         = 0
	numaStatColumnSliceLength = 2
	cgroupMemorySwapLimit     = "memory.memsw.limit_in_bytes"
	cgroupMemoryLimit         = "memory.limit_in_bytes"
	cgroupMemoryPagesByNuma   = "memory.numa_stat"
	cgroupMemoryUsage         = "memory.usage_in_bytes"
	cgroupMemoryMaxUsage      = "memory.max_usage_in_bytes"
)

type MemoryGroup struct {
}

func (s *MemoryGroup) Name() string {
	return "memory"
}

func (s *MemoryGroup) Apply(path string, d *cgroupData) (err error) {
	if path == "" {
		return nil
	}
	if memoryAssigned(d.config) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if err := os.MkdirAll(path, 0755); err != nil {
				return err
			}
			// Only enable kernel memory accouting when this cgroup
			// is created by libcontainer, otherwise we might get
			// error when people use `cgroupsPath` to join an existed
			// cgroup whose kernel memory is not initialized.
			if err := EnableKernelMemoryAccounting(path); err != nil {
				return err
			}
		}
	}
	defer func() {
		if err != nil {
			os.RemoveAll(path)
		}
	}()

	// We need to join memory cgroup after set memory limits, because
	// kmem.limit_in_bytes can only be set when the cgroup is empty.
	return join(path, d.pid)
}

func setMemory(path string, val int64) error {
	if val == 0 {
		return nil
	}

	err := fscommon.WriteFile(path, cgroupMemoryLimit, strconv.FormatInt(val, 10))
	if !errors.Is(err, unix.EBUSY) {
		return err
	}

	// EBUSY means the kernel can't set new limit as it's too low
	// (lower than the current usage). Return more specific error.
	usage, err := fscommon.GetCgroupParamUint(path, cgroupMemoryUsage)
	if err != nil {
		return err
	}
	max, err := fscommon.GetCgroupParamUint(path, cgroupMemoryMaxUsage)
	if err != nil {
		return err
	}

	return errors.Errorf("unable to set memory limit to %d (current usage: %d, peak usage: %d)", val, usage, max)
}

func setSwap(path string, val int64) error {
	if val == 0 {
		return nil
	}

	return fscommon.WriteFile(path, cgroupMemorySwapLimit, strconv.FormatInt(val, 10))
}

func setMemoryAndSwap(path string, r *configs.Resources) error {
	// If the memory update is set to -1 and the swap is not explicitly
	// set, we should also set swap to -1, it means unlimited memory.
	if r.Memory == -1 && r.MemorySwap == 0 {
		// Only set swap if it's enabled in kernel
		if cgroups.PathExists(filepath.Join(path, cgroupMemorySwapLimit)) {
			r.MemorySwap = -1
		}
	}

	// When memory and swap memory are both set, we need to handle the cases
	// for updating container.
	if r.Memory != 0 && r.MemorySwap != 0 {
		curLimit, err := fscommon.GetCgroupParamUint(path, cgroupMemoryLimit)
		if err != nil {
			return err
		}

		// When update memory limit, we should adapt the write sequence
		// for memory and swap memory, so it won't fail because the new
		// value and the old value don't fit kernel's validation.
		if r.MemorySwap == -1 || curLimit < uint64(r.MemorySwap) {
			if err := setSwap(path, r.MemorySwap); err != nil {
				return err
			}
			if err := setMemory(path, r.Memory); err != nil {
				return err
			}
			return nil
		}
	}

	if err := setMemory(path, r.Memory); err != nil {
		return err
	}
	if err := setSwap(path, r.MemorySwap); err != nil {
		return err
	}

	return nil
}

func (s *MemoryGroup) Set(path string, cgroup *configs.Cgroup) error {
	if err := setMemoryAndSwap(path, cgroup.Resources); err != nil {
		return err
	}

	if cgroup.Resources.KernelMemory != 0 {
		if err := setKernelMemory(path, cgroup.Resources.KernelMemory); err != nil {
			return err
		}
	}

	if cgroup.Resources.MemoryReservation != 0 {
		if err := fscommon.WriteFile(path, "memory.soft_limit_in_bytes", strconv.FormatInt(cgroup.Resources.MemoryReservation, 10)); err != nil {
			return err
		}
	}

	if cgroup.Resources.KernelMemoryTCP != 0 {
		if err := fscommon.WriteFile(path, "memory.kmem.tcp.limit_in_bytes", strconv.FormatInt(cgroup.Resources.KernelMemoryTCP, 10)); err != nil {
			return err
		}
	}
	if cgroup.Resources.OomKillDisable {
		if err := fscommon.WriteFile(path, "memory.oom_control", "1"); err != nil {
			return err
		}
	}
	if cgroup.Resources.MemorySwappiness == nil || int64(*cgroup.Resources.MemorySwappiness) == -1 {
		return nil
	} else if *cgroup.Resources.MemorySwappiness <= 100 {
		if err := fscommon.WriteFile(path, "memory.swappiness", strconv.FormatUint(*cgroup.Resources.MemorySwappiness, 10)); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("invalid value:%d. valid memory swappiness range is 0-100", *cgroup.Resources.MemorySwappiness)
	}

	return nil
}

func (s *MemoryGroup) GetStats(path string, stats *cgroups.Stats) error {
	// Set stats from memory.stat.
	statsFile, err := os.Open(filepath.Join(path, "memory.stat"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer statsFile.Close()

	sc := bufio.NewScanner(statsFile)
	for sc.Scan() {
		t, v, err := fscommon.GetCgroupParamKeyValue(sc.Text())
		if err != nil {
			return fmt.Errorf("failed to parse memory.stat (%q) - %v", sc.Text(), err)
		}
		stats.MemoryStats.Stats[t] = v
	}
	stats.MemoryStats.Cache = stats.MemoryStats.Stats["cache"]

	memoryUsage, err := getMemoryData(path, "")
	if err != nil {
		return err
	}
	stats.MemoryStats.Usage = memoryUsage
	swapUsage, err := getMemoryData(path, "memsw")
	if err != nil {
		return err
	}
	stats.MemoryStats.SwapUsage = swapUsage
	kernelUsage, err := getMemoryData(path, "kmem")
	if err != nil {
		return err
	}
	stats.MemoryStats.KernelUsage = kernelUsage
	kernelTCPUsage, err := getMemoryData(path, "kmem.tcp")
	if err != nil {
		return err
	}
	stats.MemoryStats.KernelTCPUsage = kernelTCPUsage

	useHierarchy := strings.Join([]string{"memory", "use_hierarchy"}, ".")
	value, err := fscommon.GetCgroupParamUint(path, useHierarchy)
	if err != nil {
		return err
	}
	if value == 1 {
		stats.MemoryStats.UseHierarchy = true
	}

	pagesByNUMA, err := getPageUsageByNUMA(path)
	if err != nil {
		return err
	}
	stats.MemoryStats.PageUsageByNUMA = pagesByNUMA

	return nil
}

func memoryAssigned(cgroup *configs.Cgroup) bool {
	return cgroup.Resources.Memory != 0 ||
		cgroup.Resources.MemoryReservation != 0 ||
		cgroup.Resources.MemorySwap > 0 ||
		cgroup.Resources.KernelMemory > 0 ||
		cgroup.Resources.KernelMemoryTCP > 0 ||
		cgroup.Resources.OomKillDisable ||
		(cgroup.Resources.MemorySwappiness != nil && int64(*cgroup.Resources.MemorySwappiness) != -1)
}

func getMemoryData(path, name string) (cgroups.MemoryData, error) {
	memoryData := cgroups.MemoryData{}

	moduleName := "memory"
	if name != "" {
		moduleName = strings.Join([]string{"memory", name}, ".")
	}
	usage := strings.Join([]string{moduleName, "usage_in_bytes"}, ".")
	maxUsage := strings.Join([]string{moduleName, "max_usage_in_bytes"}, ".")
	failcnt := strings.Join([]string{moduleName, "failcnt"}, ".")
	limit := strings.Join([]string{moduleName, "limit_in_bytes"}, ".")

	value, err := fscommon.GetCgroupParamUint(path, usage)
	if err != nil {
		if moduleName != "memory" && os.IsNotExist(err) {
			return cgroups.MemoryData{}, nil
		}
		return cgroups.MemoryData{}, fmt.Errorf("failed to parse %s - %v", usage, err)
	}
	memoryData.Usage = value
	value, err = fscommon.GetCgroupParamUint(path, maxUsage)
	if err != nil {
		if moduleName != "memory" && os.IsNotExist(err) {
			return cgroups.MemoryData{}, nil
		}
		return cgroups.MemoryData{}, fmt.Errorf("failed to parse %s - %v", maxUsage, err)
	}
	memoryData.MaxUsage = value
	value, err = fscommon.GetCgroupParamUint(path, failcnt)
	if err != nil {
		if moduleName != "memory" && os.IsNotExist(err) {
			return cgroups.MemoryData{}, nil
		}
		return cgroups.MemoryData{}, fmt.Errorf("failed to parse %s - %v", failcnt, err)
	}
	memoryData.Failcnt = value
	value, err = fscommon.GetCgroupParamUint(path, limit)
	if err != nil {
		if moduleName != "memory" && os.IsNotExist(err) {
			return cgroups.MemoryData{}, nil
		}
		return cgroups.MemoryData{}, fmt.Errorf("failed to parse %s - %v", limit, err)
	}
	memoryData.Limit = value

	return memoryData, nil
}

func getPageUsageByNUMA(cgroupPath string) (cgroups.PageUsageByNUMA, error) {
	stats := cgroups.PageUsageByNUMA{}

	file, err := os.Open(path.Join(cgroupPath, cgroupMemoryPagesByNuma))
	if os.IsNotExist(err) {
		return stats, nil
	} else if err != nil {
		return stats, err
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var statsType string
		statsByType := cgroups.PageStats{Nodes: map[uint8]uint64{}}
		columns := strings.SplitN(scanner.Text(), numaStatColumnSeparator, numaStatMaxColumns)

		for _, column := range columns {
			pagesByNode := strings.SplitN(column, numaStatKeyValueSeparator, numaStatColumnSliceLength)

			if strings.HasPrefix(pagesByNode[numaStatTypeIndex], numaNodeSymbol) {
				nodeID, err := strconv.ParseUint(pagesByNode[numaStatTypeIndex][1:], 10, 8)
				if err != nil {
					return cgroups.PageUsageByNUMA{}, err
				}

				statsByType.Nodes[uint8(nodeID)], err = strconv.ParseUint(pagesByNode[numaStatValueIndex], 0, 64)
				if err != nil {
					return cgroups.PageUsageByNUMA{}, err
				}
			} else {
				statsByType.Total, err = strconv.ParseUint(pagesByNode[numaStatValueIndex], 0, 64)
				if err != nil {
					return cgroups.PageUsageByNUMA{}, err
				}

				statsType = pagesByNode[numaStatTypeIndex]
			}

			err := addNUMAStatsByType(&stats, statsByType, statsType)
			if err != nil {
				return cgroups.PageUsageByNUMA{}, err
			}
		}
	}
	err = scanner.Err()
	if err != nil {
		return cgroups.PageUsageByNUMA{}, err
	}

	return stats, nil
}

func addNUMAStatsByType(stats *cgroups.PageUsageByNUMA, byTypeStats cgroups.PageStats, statsType string) error {
	switch statsType {
	case "total":
		stats.Total = byTypeStats
	case "file":
		stats.File = byTypeStats
	case "anon":
		stats.Anon = byTypeStats
	case "unevictable":
		stats.Unevictable = byTypeStats
	case "hierarchical_total":
		stats.Hierarchical.Total = byTypeStats
	case "hierarchical_file":
		stats.Hierarchical.File = byTypeStats
	case "hierarchical_anon":
		stats.Hierarchical.Anon = byTypeStats
	case "hierarchical_unevictable":
		stats.Hierarchical.Unevictable = byTypeStats
	default:
		return fmt.Errorf("unsupported NUMA page type found: %s", statsType)
	}
	return nil
}
