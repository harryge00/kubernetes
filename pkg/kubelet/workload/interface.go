package workload

import (
cadvisorapi "github.com/google/cadvisor/info/v1"
)

type AppWorkload interface {
	RecordWorkLoad(key string, value cadvisorapi.MetricVal)
	GetWorkLoad(key string) []cadvisorapi.MetricVal
	DeleteWorkLoad(key string)
}
