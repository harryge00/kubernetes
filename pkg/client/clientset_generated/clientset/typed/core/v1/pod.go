/*
Copyright 2017 The Kubernetes Authors.

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

package v1

import (
	"encoding/json"
	"time"
	"fmt"

	time_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	api "k8s.io/kubernetes/pkg/api"
	rest "k8s.io/client-go/rest"
	v1 "k8s.io/kubernetes/pkg/api/v1"
	scheme "k8s.io/kubernetes/pkg/client/clientset_generated/clientset/scheme"

	"github.com/golang/glog"
	util "k8s.io/kubernetes/pkg/util/podchanges"
)

// PodsGetter has a method to return a PodInterface.
// A group's client should implement this interface.
type PodsGetter interface {
	Pods(namespace string) PodInterface
}

// PodInterface has methods to work with Pod resources.
type PodInterface interface {
	Create(*v1.Pod) (*v1.Pod, error)
	Update(*v1.Pod) (*v1.Pod, error)
	UpdateStatus(*v1.Pod) (*v1.Pod, error)
	Delete(name string, options *meta_v1.DeleteOptions) error
	DeleteCollection(options *meta_v1.DeleteOptions, listOptions meta_v1.ListOptions) error
	Get(name string, options meta_v1.GetOptions) (*v1.Pod, error)
	List(opts meta_v1.ListOptions) (*v1.PodList, error)
	Watch(opts meta_v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1.Pod, err error)
	PodExpansion
}

// pods implements PodInterface
type pods struct {
	client rest.Interface
	ns     string
}

// newPods returns a Pods
func newPods(c *CoreV1Client, namespace string) *pods {
	return &pods{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Create takes the representation of a pod and creates it.  Returns the server's representation of the pod, and an error, if there is any.
func (c *pods) Create(pod *v1.Pod) (result *v1.Pod, err error) {
	result = &v1.Pod{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("pods").
		Body(pod).
		Do().
		Into(result)
	return
}

// Update takes the representation of a pod and updates it. Returns the server's representation of the pod, and an error, if there is any.
func (c *pods) Update(pod *v1.Pod) (result *v1.Pod, err error) {
	result = &v1.Pod{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("pods").
		Name(pod.Name).
		Body(pod).
		Do().
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclientstatus=false comment above the type to avoid generating UpdateStatus().

func (c *pods) UpdateStatus(pod *v1.Pod) (result *v1.Pod, err error) {
	result = &v1.Pod{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("pods").
		Name(pod.Name).
		SubResource("status").
		Body(pod).
		Do().
		Into(result)
	return
}

// Delete takes name of the pod and deletes it. Returns an error if one occurs.
func (c *pods) Delete(name string, options *meta_v1.DeleteOptions) error {
	opt := meta_v1.GetOptions{}
	pod, err := c.Get(name, opt)
	res := c.client.Delete().
		Namespace(c.ns).
		Resource("pods").
		Name(name).
		Body(options).
		Do().
		Error()
	if err == nil && res == nil && pod != nil {
		if len(pod.OwnerReferences) > 0 {
			ref := pod.OwnerReferences[0]
			if ref.Kind == "ReplicationController" {
				c.RecordRCEvent(ref.Name, pod.Namespace ,pod.Name, "RcUpdate", "RcPodDelete")
			}

			if ref.Kind == "Job" {
				c.RecordJobEvent(ref.Name, pod.Namespace ,pod.Name, "JobUpdate", "JobPodDelete")
			}
		}
	}
	return res
}

// DeleteCollection deletes a collection of objects.
func (c *pods) DeleteCollection(options *meta_v1.DeleteOptions, listOptions meta_v1.ListOptions) error {
	pods, err := c.List(listOptions)
	res := c.client.Delete().
		Namespace(c.ns).
		Resource("pods").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Body(options).
		Do().
		Error()

	if res == nil && err == nil {
		for _, pod := range pods.Items {
			if len(pod.OwnerReferences) > 0 {
				ref := pod.OwnerReferences[0]
				if ref.Kind == "ReplicationController" {
					c.RecordRCEvent(ref.Name, pod.Namespace ,pod.Name, "RcUpdate", "RcPodDelete")
				}

				if ref.Kind == "Job" {
					c.RecordJobEvent(ref.Name, pod.Namespace ,pod.Name, "JobUpdate", "JobPodDelete")
				}
			}
		}
	}
	return res
}

// Get takes name of the pod, and returns the corresponding pod object, and an error if there is any.
func (c *pods) Get(name string, options meta_v1.GetOptions) (result *v1.Pod, err error) {
	result = &v1.Pod{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("pods").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of Pods that match those selectors.
func (c *pods) List(opts meta_v1.ListOptions) (result *v1.PodList, err error) {
	result = &v1.PodList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("pods").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested pods.
func (c *pods) Watch(opts meta_v1.ListOptions) (watch.Interface, error) {
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("pods").
		VersionedParams(&opts, scheme.ParameterCodec).
		Watch()
}

// Patch applies the patch and returns the patched pod.
func (c *pods) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1.Pod, err error) {
	result = &v1.Pod{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("pods").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}


func (c *pods) RecordJobEvent(jobName, namespace, podName, event, action string) {
	ref := &v1.ObjectReference{
		Kind:      "job-controller",
		Name:      podName,
		Namespace: namespace,
	}
	glog.V(2).Infof("Recording %s event message for replication %s", event, jobName)
	transformation := util.JobTransformation{
		JobName: jobName,
		Namespace: namespace,
		PodName: podName,
		EventType: event,
		Action: action,
	}
	message,_ := json.Marshal(transformation)

	c.sendEvent(ref, "JobUpdate", fmt.Sprintf("%s", string(message)))
}

func (c *pods) RecordRCEvent(rcName, namespace, podName, event, action string) {
	ref := &v1.ObjectReference{
		Kind:      "replication-controller",
		Name:      podName,
		Namespace: namespace,
	}
	glog.V(2).Infof("Recording %s event message for replication %s", event, rcName)
	transformation := util.Transformation{
		RcName: rcName,
		Namespace: namespace,
		PodName: podName,
		EventType: event,
		Action: action,
	}
	message,_ := json.Marshal(transformation)

	c.sendEvent(ref, "RcUpdate", fmt.Sprintf("%s", string(message)))
}

func (c *pods) sendEvent(ref *v1.ObjectReference, reason, message string) {
	event := makeEvent(ref, api.EventTypeNormal, reason, message)
	event.Source = v1.EventSource{Component: "client",}
	result := &v1.Event{}
	err := c.client.Post().
		Namespace(c.ns).
		Resource("events").
		Body(event).
		Do().
		Into(result)
	if err != nil {
		glog.Errorf("Could not construct event: '%#v' due to: '%v'. Will not report event: '%v' '%v' '%v'", ref.Name , err, api.EventTypeNormal, reason, message)
	}
}

func makeEvent(ref *v1.ObjectReference, eventtype, reason, message string) *v1.Event {
	t := time_v1.Time{Time: time.Now() }
	namespace := ref.Namespace
	if namespace == "" {
		namespace = api.NamespaceDefault
	}
	return &v1.Event{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      fmt.Sprintf("%v.%x", ref.Name, t.UnixNano()),
			Namespace: namespace,
		},
		InvolvedObject: *ref,
		Reason:        reason,
		Message:        message,
		FirstTimestamp: t,
		LastTimestamp:  t,
		Count:          1,
		Type:           eventtype,
	}
}