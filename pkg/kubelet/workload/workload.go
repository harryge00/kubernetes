package workload
import (
	cadvisorapi "github.com/google/cadvisor/info/v1"
	"github.com/golang/glog"
//	"sync"
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


func NewMetricsCache(maxcon int, maxrecord int32)  (AppWorkload) {
	metricsCache := &MetricsCache{
		ContainerWorkload: make(map[string][]cadvisorapi.MetricVal, maxcon),
		SampleWindow: maxrecord,
	}
	return metricsCache
}

func (kl *MetricsCache) RecordWorkLoad(key string, value cadvisorapi.MetricVal) {
	glog.V(3).Infof("Number of data to retain: %d", length)
	glog.V(2).Info("Record sample workload data for container: ", key)
	glog.V(3).Infof("Original WorkLoad Record: %+v", kl.ContainerWorkload[key])
	if len(kl.ContainerWorkload[key]) < int(length) {
		kl.ContainerWorkload[key] = append(kl.ContainerWorkload[key], value)
	} else{
		kl.ContainerWorkload[key] = append(kl.ContainerWorkload[key][1:len(kl.ContainerWorkload[key])], value)
	}
	glog.V(3).Infof("Newest WorkLoad: %+v", kl.ContainerWorkload[key][len(kl.ContainerWorkload[key])-1])
	glog.V(2).Info("Length of sample workload data for container { ", key, "} is: ", len(kl.ContainerWorkload[key]) )
	glog.V(2).Info("Length of sample workload data is: ", len(kl.ContainerWorkload) )
}

func (kl *MetricsCache) GetWorkLoad(key string) []cadvisorapi.MetricVal {
	glog.V(2).Info("Reading recorded metrics..., KEY is ", key, "RET is: %+v", kl.ContainerWorkload[key])
	return kl.ContainerWorkload[key]
}

func (kl *MetricsCache) DeleteWorkLoad(key string) {
	glog.V(2).Info("Deleting the not existed container: ", key)
	glog.V(2).Info("Length01 is: ", len(kl.ContainerWorkload) )
	_, ok := kl.ContainerWorkload[key]
	if ok {
		delete(kl.ContainerWorkload, key)
		glog.V(2).Info("Length02 is: ", len(kl.ContainerWorkload) )
	}
}
/*
type WorkLoadSample struct{
	WorkLoad int32
	Timestamp  time.Time
}
*/