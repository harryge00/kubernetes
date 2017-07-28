/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package prober

import (
	"math/rand"
	"time"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/kubernetes/pkg/api/v1"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/prober/results"
	"k8s.io/kubernetes/pkg/kubelet/util/format"
	"encoding/json"
	"bytes"
	"k8s.io/kubernetes/pkg/kubelet/workload"
//	"k8s.io/kubernetes/pkg/kubelet"
//	"k8s.io/kubernetes/pkg/kubelet/workload/data"
	cadvisorapi "github.com/google/cadvisor/info/v1"
//	"k8s.io/kubernetes/pkg/kubelet/workload"
)

// worker handles the periodic probing of its assigned container. Each worker has a go-routine
// associated with it which runs the probe loop until the container permanently terminates, or the
// stop channel is closed. The worker uses the probe Manager's statusManager to get up-to-date
// container IDs.
type worker struct {
	// Channel for stopping the probe.
	stopCh chan struct{}

	// The pod containing this probe (read-only)
	pod *v1.Pod

	// The container to probe (read-only)
	container v1.Container

	// Describes the probe configuration (read-only)
	spec *v1.Probe

	// The type of the worker.
	probeType probeType

	// The probe value during the initial delay.
	initialValue results.Result

	// Where to store this workers results.
	resultsManager results.Manager
	probeManager   *manager

	// The last known container ID for this worker.
	containerID kubecontainer.ContainerID
	// The last probe result for this worker.
	lastResult results.Result
	// How many times in a row the probe has returned the same result.
	resultRun int

	// If set, skip probing.
	onHold bool

//	workloadHandler  runtime.WorkloadHandler
}

// Creates and starts a new probe worker.
func newWorker(
	m *manager,
	probeType probeType,
	pod *v1.Pod,
	container v1.Container) *worker {

	w := &worker{
		stopCh:       make(chan struct{}, 1), // Buffer so stop() can be non-blocking.
		pod:          pod,
		container:    container,
		probeType:    probeType,
		probeManager: m,
	}
	//TODO：

	switch probeType {
	case readiness:
		w.spec = container.ReadinessProbe
		w.resultsManager = m.readinessManager
		w.initialValue = results.Failure
	case liveness:
		w.spec = container.LivenessProbe
		w.resultsManager = m.livenessManager
		w.initialValue = results.Success
	case service:
		w.spec = container.ServiceProbe
		w.resultsManager = m.serviceManager
		w.initialValue = results.Failure

	}
	return w
}

/*
func (w *worker) SetWorkload(workloadHandler runtime.WorkloadHandler) {
	w.workloadHandler = workloadHandler
}
*/

// run periodically probes the container.
//func (w *worker) run( kl *kubelet.Kubelet) {
func (w *worker) run() {
	probeTickerPeriod := time.Duration(w.spec.PeriodSeconds) * time.Second
	probeTicker := time.NewTicker(probeTickerPeriod)

	defer func() {
		// Clean up.
		probeTicker.Stop()
		if !w.containerID.IsEmpty() {
			w.resultsManager.Remove(w.containerID)
		}

		w.probeManager.removeWorker(w.pod.UID, w.container.Name, w.probeType)

		glog.V(3).Infof("Need delete some workload data if container stopped or killed")
		var buf bytes.Buffer
		buf.WriteString(w.pod.Namespace)
		buf.WriteString("_")
		buf.WriteString(w.pod.Name)
		buf.WriteString("_")
		buf.WriteString(w.container.Name)

		key := buf.String()
		glog.V(3).Infof("Delete workload data for container: ", key)
		handler := workload.DefaultMetricsCache
		glog.V(3).Infof("Container Workload is: %+v", handler.GetWorkLoad(key))
		defer handler.DeleteWorkLoad(key)

	}()

	// If kubelet restarted the probes could be started in rapid succession.
	// Let the worker wait for a random portion of tickerPeriod before probing.
	time.Sleep(time.Duration(rand.Float64() * float64(probeTickerPeriod)))

probeLoop:
	for w.doProbe() {
		// Wait for next probe tick.
		select {
		case <-w.stopCh:
/*
			glog.V(3).Infof("Need delete some workload data if container stopped or killed")
			var buf bytes.Buffer
			buf.WriteString(w.pod.Namespace)
			buf.WriteString("_")
			buf.WriteString(w.pod.Name)
			buf.WriteString("_")
			buf.WriteString(w.container.Name)

			key := buf.String()
			glog.V(3).Infof("Delete workload data for container: ", key)
			handler := workload.DefaultMetricsCache
			defer handler.DeleteWorkLoad(key)
*/
			break probeLoop
		case <-probeTicker.C:
			// continue
		}
	}
}

// stop stops the probe worker. The worker handles cleanup and removes itself from its manager.
// It is safe to call stop multiple times.
func (w *worker) stop() {
	select {
	case w.stopCh <- struct{}{}:
	default: // Non-blocking.
	}
}

// doProbe probes the container once and records the result.
// Returns whether the worker should continue.
// func (w *worker) doProbe(kl *kubelet.Kubelet) (keepGoing bool) {
func (w *worker) doProbe() (keepGoing bool) {
	defer func() { recover() }() // Actually eat panics (HandleCrash takes care of logging)
	defer runtime.HandleCrash(func(_ interface{}) { keepGoing = true })
	//defer workload.DeleteWorkload(w.container.Name)

	status, ok := w.probeManager.statusManager.GetPodStatus(w.pod.UID)
	if !ok {
		// Either the pod has not been created yet, or it was already deleted.
		glog.V(3).Infof("No status for pod: %v", format.Pod(w.pod))
		return true
	}

	// Worker should terminate if pod is terminated.
	if status.Phase == v1.PodFailed || status.Phase == v1.PodSucceeded {
		glog.V(3).Infof("Pod %v %v, exiting probe worker",
			format.Pod(w.pod), status.Phase)
		return false
	}

	c, ok := v1.GetContainerStatus(status.ContainerStatuses, w.container.Name)
	if !ok || len(c.ContainerID) == 0 {
		// Either the container has not been created yet, or it was deleted.
		glog.V(3).Infof("Probe target container not found: %v - %v",
			format.Pod(w.pod), w.container.Name)
		return true // Wait for more information.
	}

	if w.containerID.String() != c.ContainerID {
		if !w.containerID.IsEmpty() {
			w.resultsManager.Remove(w.containerID)
		}
		w.containerID = kubecontainer.ParseContainerID(c.ContainerID)
		w.resultsManager.Set(w.containerID, w.initialValue, w.pod)
		// We've got a new container; resume probing.
		w.onHold = false
	}

	if w.onHold {
		// Worker is on hold until there is a new container.
		return true
	}

	if c.State.Running == nil {
		glog.V(3).Infof("Non-running container probed: %v - %v",
			format.Pod(w.pod), w.container.Name)
		if !w.containerID.IsEmpty() {
			w.resultsManager.Set(w.containerID, results.Failure, w.pod)
		}
		// Abort if the container will not be restarted.
		return c.State.Terminated == nil ||
			w.pod.Spec.RestartPolicy != v1.RestartPolicyNever
	}

	if int32(time.Since(c.State.Running.StartedAt.Time).Seconds()) < w.spec.InitialDelaySeconds {
		return true
	}

	now := time.Now()
	// TODO: in order for exec probes to correctly handle downward API env, we must be able to reconstruct
	// the full container environment here, OR we must make a call to the CRI in order to get those environment
	// values from the running container.
	result, output, err := w.probeManager.prober.probe(w.probeType, w.pod, status, w.container, w.containerID)
	if err != nil {
		// Prober error, throw away the result.
		return true
	}

	handler := workload.DefaultMetricsCache
	if w.probeType == service && result == results.Success {
		var scaleinfoIn []byte
		var scaleinfoOut ScaleInfo
		scaleinfoIn = []byte(output)
		//	if err = json.Unmarshal(scaleinfo_in, scaleinfo_out); err != nil {
		if err = json.Unmarshal(scaleinfoIn, &scaleinfoOut); err != nil {
			glog.V(3).Infof("Response: %+v, errored: %v", scaleinfoIn, err)
			return true
		}
		c.IsScale = scaleinfoOut.IsScale
		c.WorkLoad = scaleinfoOut.Workload
		// 默认情况下 Pod 是可缩容的(v1.PodStatus.IsScale = ture), 当且仅当某个容器的 serviceProbe 探测结果是不可缩容时进行状态更新
		if !c.IsScale {
			status.IsScale = c.IsScale
		}

		var buf bytes.Buffer
		buf.WriteString(w.pod.Namespace)
		buf.WriteString("_")
		buf.WriteString(w.pod.Name)
		buf.WriteString("_")
		buf.WriteString(w.container.Name)

		key := buf.String()
		glog.V(3).Infof("Unique container name is: %s", key)
	//	defer handler.DeleteWorkLoad(key)

		for i, _ := range status.ContainerStatuses {
			if status.ContainerStatuses[i].Name == w.container.Name {
				status.ContainerStatuses[i].IsScale = c.IsScale
				status.ContainerStatuses[i].WorkLoad = c.WorkLoad


				//value := kubelet.WorkLoadSample{
/*
					value :=runtime.WorkLoadSample{
					WorkLoad: c.WorkLoad,
					Timestamp:  now,
					Label: w.container.Name,
				}
*/
				value := cadvisorapi.MetricVal{
					Label: "workload",
					Timestamp: now,
					IntValue: int64(c.WorkLoad),
				//	FloatValue: ,
				}
				glog.V(3).Infof("Sample value for this time is: %+v", value)
			//	glog.V(3).Infof("WORKLOADHANDLER: %+v", &w.workloadHandler)

				//workload.WriteWorkLoad(key, value)
			//	w.workloadHandler.RecordWorkLoad(key, value)
			//	workload.AppWorkload.RecordWorkLoad(key,value)
			//	data.RecordWorkload(workload.AppWorkload())
			//	aw := workload.AppWorkload()
			//	in.RecordWorkload(key, value)
				handler.RecordWorkLoad(key, value)
			//	workload.AppWorkload.RecordWorkLoad(key, value)
				glog.V(3).Infof("Finished Recording Data")
				break
			}
		}
		glog.V(3).Infof("ServiceProbe Pod status for pod: %v", format.Pod(w.pod))
		w.probeManager.statusManager.SetPodStatus(w.pod, status)
	}

	if w.lastResult == result {
		w.resultRun++
	} else {
		w.lastResult = result
		w.resultRun = 1
	}

	if (result == results.Failure && w.resultRun < int(w.spec.FailureThreshold)) ||
		(result == results.Success && w.resultRun < int(w.spec.SuccessThreshold)) {
		// Success or failure is below threshold - leave the probe state unchanged.
		return true
	}

	w.resultsManager.Set(w.containerID, result, w.pod)

	if w.probeType == liveness && result == results.Failure {
		// The container fails a liveness check, it will need to be restarted.
		// Stop probing until we see a new container ID. This is to reduce the
		// chance of hitting #21751, where running `docker exec` when a
		// container is being stopped may lead to corrupted container state.
		w.onHold = true
	}

	return true
}

//结构化存储 Api 返回的 JSON 数据，注意字段首字母必须大写
type ScaleInfo struct {
	Workload     int32 `json:"workload"`
	IsScale       bool `json:"isScale"`
}


/*
type WorkLoadSample struct{
	WorkLoad int32
	Timestamp  time.Time
}
*/
/*
func WriteWorkLoad(key string, value kubelet.WorkLoadSample) {
	kubelet.Kubelet.RecordWorkLoad(key, value)
}

func GetWorkLoad() *kubelet.ContainerWorkLoad{
	return kubelet.Kubelet.GetWorkLoad()
}
*/

