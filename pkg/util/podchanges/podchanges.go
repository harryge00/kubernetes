package podchanges

import (
	"encoding/json"
	"k8s.io/client-go/tools/record"
	"k8s.io/kubernetes/pkg/api"

	clientv1 "k8s.io/client-go/pkg/api/v1"
)

// Both RcPodChange and RcStatusChange will use it.
type RcChangeEvent struct {
	EventType     string `json:"eventType,omitempty"`
	Namespace     string `json:"namespace,omitempty"`
	PodName       string `json:"podName,omitempty"`
	RcName        string `json:"rcName,omitempty"`
	Action        string `json:"action,omitempty"`
	Room          string `json:"room,omitempty"`
	ReadyReplicas int32  `json:"readyReplicas,omitempty"`
}

type StatefulsetChangeEvent struct {
	EventType     string `json:"eventType,omitempty"`
	Namespace     string `json:"namespace,omitempty"`
	PodName       string `json:"podName,omitempty"`
	SsName        string `json:"ssName,omitempty"`
	Action        string `json:"action,omitempty"`
	Room          string `json:"room,omitempty"`
	ReadyReplicas int32  `json:"readyReplicas,omitempty"`
}

type JobChangeEvent struct {
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

// TODO: should extract useful information and pass them through events. Eliminate the HTTP requests to get pods/RCs in servicemanager!
func RecordRCStatusEvent(recorder record.EventRecorder, rcName, namespace, event, action string, labels map[string]string, readyReplicas int32) {
	ref := &clientv1.ObjectReference{
		Kind:      "replication-controller",
		Name:      rcName,
		Namespace: namespace,
	}
	rcChangeEvent := RcChangeEvent{
		RcName:        rcName,
		Namespace:     namespace,
		EventType:     event,
		Action:        action,
		Room:          labels["room"],
		ReadyReplicas: readyReplicas,
	}
	message, _ := json.Marshal(rcChangeEvent)

	recorder.Eventf(ref, api.EventTypeNormal, "RcStatusUpdate", "%s", string(message))
}

func RecordRCPodEvent(recorder record.EventRecorder, rcName, namespace, podName, event, action string) {
	ref := &clientv1.ObjectReference{
		Kind:      "replication-controller",
		Name:      podName,
		Namespace: namespace,
	}
	rcChangeEvent := RcChangeEvent{
		RcName:    rcName,
		Namespace: namespace,
		PodName:   podName,
		EventType: event,
		Action:    action,
	}
	message, _ := json.Marshal(rcChangeEvent)

	recorder.Eventf(ref, api.EventTypeNormal, "RcUpdate", "%s", string(message))
}

func RecordStatefulSetStatusEvent(recorder record.EventRecorder, ssName, namespace, event, action string, labels map[string]string, readyReplicas int32) {
	ref := &clientv1.ObjectReference{
		Kind:      "StatefulSet",
		Name:      ssName,
		Namespace: namespace,
	}
	changeEvent := StatefulsetChangeEvent{
		SsName:        ssName,
		Namespace:     namespace,
		EventType:     event,
		Action:        action,
		Room:          labels["room"],
		ReadyReplicas: readyReplicas,
	}
	message, _ := json.Marshal(changeEvent)

	recorder.Eventf(ref, api.EventTypeNormal, "StatefulSetStatusUpdate", "%s", string(message))
}

func RecordStatefulSetPodEvent(recorder record.EventRecorder, ssName, namespace, podName, event, action string) {
	ref := &clientv1.ObjectReference{
		Kind:      "StatefulSet",
		Name:      ssName,
		Namespace: namespace,
	}
	changeEvent := StatefulsetChangeEvent{
		SsName:    ssName,
		Namespace: namespace,
		PodName:   podName,
		EventType: event,
		Action:    action,
	}
	message, _ := json.Marshal(changeEvent)

	recorder.Eventf(ref, api.EventTypeNormal, "StatefulSetUpdate", "%s", string(message))
}

func RecordJobPodEvent(recorder record.EventRecorder, jobName, namespace, podName, event, action string) {
	ref := &clientv1.ObjectReference{
		Kind:      "job-controller",
		Name:      podName,
		Namespace: namespace,
	}

	changeEvent := JobChangeEvent{
		JobName:   jobName,
		Namespace: namespace,
		PodName:   podName,
		EventType: event,
		Action:    action,
	}
	message, _ := json.Marshal(changeEvent)

	recorder.Eventf(ref, api.EventTypeNormal, "JobUpdate", "%s", string(message))
}
