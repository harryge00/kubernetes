package podchanges

import (
	"encoding/json"
	"k8s.io/client-go/tools/record"
	"k8s.io/kubernetes/pkg/api"

	"github.com/golang/glog"
	clientv1 "k8s.io/client-go/pkg/api/v1"
)

type Transformation struct {
	EventType string `json:"eventType,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	PodName   string `json:"podName,omitempty"`
	RcName    string `json:"rcName,omitempty"`
	Action    string `json:"action,omitempty"`
}

type SSTransformation struct {
	EventType string `json:"eventType,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	PodName   string `json:"podName,omitempty"`
	SsName    string `json:"ssName,omitempty"`
	Action    string `json:"action,omitempty"`
}

type JobTransformation struct {
	EventType string `json:"eventType,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	PodName   string `json:"podName,omitempty"`
	JobName   string `json:"jobName,omitempty"`
	Action    string `json:"action,omitempty"`
}

type RcAutoScaleInfo struct {
	EventType  string `json:"eventType,omitempty"`
	RcName     string `json:"rcName,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	CurrentNum int32  `json:"currentNum,omitempty"`
	DesiredNum int32  `json:"desiredNum,omitempty"`
	Status     string `json:"status,omitempty"`
}

func RecorcRCAutoScaleEvent(recorder record.EventRecorder, rcName, namespace, eventType string, currentNum, desiredNum int32, status string) {
	ref := &clientv1.ObjectReference{
		Kind:      "replication-controller",
		Name:      "",
		Namespace: namespace,
	}
	glog.V(2).Infof("record event autoscale message for replication %s", rcName)

	autoScaleInfo := RcAutoScaleInfo{
		Namespace:  namespace,
		RcName:     rcName,
		CurrentNum: currentNum,
		DesiredNum: desiredNum,
		EventType:  eventType,
		Status:     status,
	}
	message, _ := json.Marshal(autoScaleInfo)

	recorder.Eventf(ref, api.EventTypeNormal, "RcUpdate", "%s", string(message))
}

func RecordRCEvent(recorder record.EventRecorder, rcName, namespace, podName, event, action string) {
	ref := &clientv1.ObjectReference{
		Kind:      "replication-controller",
		Name:      podName,
		Namespace: namespace,
	}
	glog.V(2).Infof("/ %s event message for replication %s", event, rcName)
	transformation := Transformation{
		RcName:    rcName,
		Namespace: namespace,
		PodName:   podName,
		EventType: event,
		Action:    action,
	}
	message, _ := json.Marshal(transformation)

	recorder.Eventf(ref, api.EventTypeNormal, "RcUpdate", "%s", string(message))
}

func RecordStatefulSetEvent(recorder record.EventRecorder, ssName, namespace, podName, event, action string) {
	ref := &clientv1.ObjectReference{
		Kind:      "StatefulSet",
		Name:      podName,
		Namespace: namespace,
	}
	glog.V(2).Infof("/ %s event message for ss %s", event, ssName)
	transformation := SSTransformation{
		SsName:    ssName,
		Namespace: namespace,
		PodName:   podName,
		EventType: event,
		Action:    action,
	}
	message, _ := json.Marshal(transformation)

	recorder.Eventf(ref, api.EventTypeNormal, "StatefulSetUpdate", "%s", string(message))
}

func RecordJobEvent(recorder record.EventRecorder, jobName, namespace, podName, event, action string) {
	ref := &clientv1.ObjectReference{
		Kind:      "job-controller",
		Name:      podName,
		Namespace: namespace,
	}

	glog.V(2).Infof("Recording %s event message for Job %s", event, jobName)
	transformation := JobTransformation{
		JobName:   jobName,
		Namespace: namespace,
		PodName:   podName,
		EventType: event,
		Action:    action,
	}
	message, _ := json.Marshal(transformation)

	recorder.Eventf(ref, api.EventTypeNormal, "JobUpdate", "%s", string(message))
}
