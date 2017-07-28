package workload
import (
	cadvisorapi "github.com/google/cadvisor/info/v1"
)

const (
	// The number of workload sample data to retain for one container
	length = 256
)

var DefaultMetricsCache = NewMetricsCache(200, 256)

type  MetricsCache struct {
	// containerWorkLoad contains certain number of sample result of ServiceProbe (workLoad) for container
	// For each container it should be a limited length
	//	ContainerWorkLoad []map[string][]int32
	ContainerWorkload  map[string][]cadvisorapi.MetricVal
	//	containerWorkload *map[string][]WorkLoadSample
	// samplewindow indicate the number of latest sample result of ServiceProbe (workLoad) to remained
	SampleWindow int32
}

//TODO(wangzhuzhen): Need to use kubelet's option sample-window limit the value of SampleWindow
func NewMetricsCache(maxcon int, maxrecord int32)  (AppWorkload) {
	metricsCache := &MetricsCache{
		ContainerWorkload: make(map[string][]cadvisorapi.MetricVal, maxcon),
		SampleWindow: maxrecord,
	}
	return metricsCache
}

// RecordWorkLoad record the workload data acquire by ServiceProbe as CustomMetrics for one container
func (kl *MetricsCache) RecordWorkLoad(key string, value cadvisorapi.MetricVal) {
	if len(kl.ContainerWorkload[key]) < int(length) {
		kl.ContainerWorkload[key] = append(kl.ContainerWorkload[key], value)
	} else{
		kl.ContainerWorkload[key] = append(kl.ContainerWorkload[key][1:len(kl.ContainerWorkload[key])], value)
	}
}

// GetWorkLoad get the workload data acquire by ServiceProbe for one container
func (kl *MetricsCache) GetWorkLoad(key string) []cadvisorapi.MetricVal {
	return kl.ContainerWorkload[key]
}

func (kl *MetricsCache) DeleteWorkLoad(key string) {
	_, ok := kl.ContainerWorkload[key]
	if ok {
		delete(kl.ContainerWorkload, key)
	}
}