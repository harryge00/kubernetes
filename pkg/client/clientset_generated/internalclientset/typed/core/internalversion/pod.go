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

package internalversion

import (
	"encoding/json"
	"time"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
	api "k8s.io/kubernetes/pkg/api"
	scheme "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/scheme"

	"github.com/golang/glog"
	util "k8s.io/kubernetes/pkg/util/podchanges"
	"fmt"
)

// PodsGetter has a method to return a PodInterface.
// A group's client should implement this interface.
type PodsGetter interface {
	Pods(namespace string) PodInterface
}

// PodInterface has methods to work with Pod resources.
type PodInterface interface {
	Create(*api.Pod) (*api.Pod, error)
	Update(*api.Pod) (*api.Pod, error)
	UpdateStatus(*api.Pod) (*api.Pod, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*api.Pod, error)
	List(opts v1.ListOptions) (*api.PodList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *api.Pod, err error)
	PodExpansion
}

// pods implements PodInterface
type pods struct {
	client rest.Interface
	ns     string
}

// newPods returns a Pods
func newPods(c *CoreClient, namespace string) *pods {
	return &pods{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Create takes the representation of a pod and creates it.  Returns the server's representation of the pod, and an error, if there is any.
func (c *pods) Create(pod *api.Pod) (result *api.Pod, err error) {
	result = &api.Pod{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("pods").
		Body(pod).
		Do().
		Into(result)
	return
}

// Update takes the representation of a pod and updates it. Returns the server's representation of the pod, and an error, if there is any.
func (c *pods) Update(pod *api.Pod) (result *api.Pod, err error) {
	result = &api.Pod{}
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

func (c *pods) UpdateStatus(pod *api.Pod) (result *api.Pod, err error) {
	result = &api.Pod{}
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
func (c *pods) Delete(name string, options *v1.DeleteOptions) error {
	opt := v1.GetOptions{}
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
func (c *pods) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
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
func (c *pods) Get(name string, options v1.GetOptions) (result *api.Pod, err error) {
	result = &api.Pod{}
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
func (c *pods) List(opts v1.ListOptions) (result *api.PodList, err error) {
	result = &api.PodList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("pods").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested pods.
func (c *pods) Watch(opts v1.ListOptions) (watch.Interface, error) {
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("pods").
		VersionedParams(&opts, scheme.ParameterCodec).
		Watch()
}

// Patch applies the patch and returns the patched pod.
func (c *pods) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *api.Pod, err error) {
	result = &api.Pod{}
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
	ref := &api.ObjectReference{
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
	ref := &api.ObjectReference{
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

func (c *pods) sendEvent(ref *api.ObjectReference, reason, message string) {
	event := makeEvent(ref, api.EventTypeNormal, reason, message)
	event.Source = api.EventSource{Component: "client",}
	result := &api.Event{}
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

func makeEvent(ref *api.ObjectReference, eventtype, reason, message string) *api.Event {
	t := v1.Time{Time: time.Now() }
	namespace := ref.Namespace
	if namespace == "" {
		namespace = api.NamespaceDefault
	}
	return &api.Event{
		ObjectMeta: v1.ObjectMeta{
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
