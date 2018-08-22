/*
Copyright 2014 The Kubernetes Authors.

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

package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/util/wait"

	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/clock"
	"k8s.io/client-go/util/integer"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/v1"
	"k8s.io/kubernetes/pkg/api/validation"
	extensions "k8s.io/kubernetes/pkg/apis/extensions/v1beta1"
	"k8s.io/kubernetes/pkg/client/clientset_generated/clientset"
	clientretry "k8s.io/kubernetes/pkg/client/retry"
	util "k8s.io/kubernetes/pkg/util/podchanges"

	"bytes"
	"github.com/golang/glog"
	"io/ioutil"
	"k8s.io/kubernetes/pkg/kubelet/network"
	"strconv"
	"strings"
)

const (
	// If a watch drops a delete event for a pod, it'll take this long
	// before a dormant controller waiting for those packets is woken up anyway. It is
	// specifically targeted at the case where some problem prevents an update
	// of expectations, without it the controller could stay asleep forever. This should
	// be set based on the expected latency of watch events.
	//
	// Currently a controller can service (create *and* observe the watch events for said
	// creation) about 10 pods a second, so it takes about 1 min to service
	// 500 pods. Just creation is limited to 20qps, and watching happens with ~10-30s
	// latency/pod at the scale of 3000 pods over 100 nodes.
	ExpectationsTimeout = 5 * time.Minute
)

var UpdateTaintBackoff = wait.Backoff{
	Steps:    5,
	Duration: 100 * time.Millisecond,
	Jitter:   1.0,
}

var (
	KeyFunc      = cache.DeletionHandlingMetaNamespaceKeyFunc
	URLSet       = false
	baseIPURL    = "http://localhost:8080"
	getIPURL     = "http://localhost:8080/api/net/ip/occupy"
	releaseIPURL = "http://localhost:8080/api/net/ip/release"
	ipLocation   = "1199"
)

type ResyncPeriodFunc func() time.Duration

// Returns 0 for resyncPeriod in case resyncing is not needed.
func NoResyncPeriodFunc() time.Duration {
	return 0
}

// StaticResyncPeriodFunc returns the resync period specified
func StaticResyncPeriodFunc(resyncPeriod time.Duration) ResyncPeriodFunc {
	return func() time.Duration {
		return resyncPeriod
	}
}

// Expectations are a way for controllers to tell the controller manager what they expect. eg:
//	ControllerExpectations: {
//		controller1: expects  2 adds in 2 minutes
//		controller2: expects  2 dels in 2 minutes
//		controller3: expects -1 adds in 2 minutes => controller3's expectations have already been met
//	}
//
// Implementation:
//	ControlleeExpectation = pair of atomic counters to track controllee's creation/deletion
//	ControllerExpectationsStore = TTLStore + a ControlleeExpectation per controller
//
// * Once set expectations can only be lowered
// * A controller isn't synced till its expectations are either fulfilled, or expire
// * Controllers that don't set expectations will get woken up for every matching controllee

// ExpKeyFunc to parse out the key from a ControlleeExpectation
var ExpKeyFunc = func(obj interface{}) (string, error) {
	if e, ok := obj.(*ControlleeExpectations); ok {
		return e.key, nil
	}
	return "", fmt.Errorf("Could not find key for obj %#v", obj)
}

type IpResp struct {
	Result  IpResult `json:"result,omitempty"`
	Code    int      `json:"code,omitempty"`
	Message string   `json:"message,omitempty"`
}

type IpRequire struct {
	Group     string `json:"group,omitempty"`
	UserId    int    `json:"userId,omitempty"`
	NetType   int    `json:"type,omitempty"`
	Location  string `json:"location,omitempty"`
	Zone      string `json:"zone,omitempty"`
	IsPrivate int    `json:"isPrivate,omitempty"`
}

type IpRelease struct {
	IP     string `json:"ip,omitempty"`
	Group  string `json:"group,omitempty"`
	UserId int    `json:"userId,omitempty"`
}

type IpResult struct {
	Routes   []string `json:"routes,omitempty"`
	IP       string   `json:"ip,omitempty"`
	Mask     int      `json:"mask,omitempty"`
	Occupied int      `json:"occupied,omitempty"`
	Location string   `json:"location,omitempty"`
}

type IpReleaseResp struct {
	Message string `json:"message,omitempty"`
	Code    int    `json:"code,omitempty"`
}

func SetIPURL(url, location string) {
	baseIPURL = url
	URLSet = true
	getIPURL = url + "/api/net/ip/occupy"
	releaseIPURL = url + "/api/net/ip/release"
	ipLocation = location
}

func GetIPMaskForPod(reqBytes []byte) (ipResp IpResp, err error) {
	resp, err := http.Post(getIPURL, "application/json", bytes.NewBuffer(reqBytes))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	err = json.Unmarshal(body, &ipResp)
	if err != nil {
		return
	}
	if ipResp.Code != 200 {
		err = fmt.Errorf("%v", ipResp.Message)
	}
	return
}

func sendReleaseIpReq(reqBytes []byte) (code int, err error) {
	resp, err := http.Post(releaseIPURL, "application/json", bytes.NewBuffer(reqBytes))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	var ipResp IpReleaseResp
	err = json.Unmarshal(body, &ipResp)
	if err != nil {
		return
	}
	code = ipResp.Code
	if code != 200 {
		err = fmt.Errorf("%v", ipResp.Message)
	}
	return
}

func ReleaseGroupedIP(namespace, group, ip string) error {
	glog.V(6).Infof("ReleaseIP %v ip %v for group: %v", namespace, ip, group)
	userIds := strings.Split(namespace, "-")
	lenIds := len(userIds)
	if lenIds <= 1 {
		err := fmt.Errorf("Wrong Namespace format %v !", namespace)
		return err
	}
	userId := userIds[lenIds-1]
	uid, err := strconv.Atoi(userId)
	if err != nil {
		return err
	}
	req := IpRelease{
		IP:     ip,
		UserId: uid,
	}
	if group != "" {
		req.Group = group
	}
	glog.V(6).Infof("ReleaseIPReq: %v", req)
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}
	// Retry 3 times in case of network error.
	for i := 0; i < 3; i++ {
		code, err := sendReleaseIpReq(reqBytes)
		if err == nil {
			return nil
		}
		glog.Errorf("Failed to release ip %v: %v", ip, err)
		if code != 0 {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	glog.V(6).Infof("IP %v successfully released.", ip)
	return err
}

func AddIPMaskIfPodLabeled(pod *v1.Pod, namespace string) (ip string, mask int, err error) {
	// No needs to add ips if no label or "ips" has already been added.
	if pod.Annotations[network.IPAnnotationKey] != "" || pod.Labels[network.NetworkKey] == "" {
		return
	}
	nets := strings.Split(pod.Labels[network.NetworkKey], "-")
	if len(nets) != 2 {
		err = fmt.Errorf("Illegal network label: %v", pod.Labels[network.NetworkKey])
		return
	}
	userIds := strings.Split(namespace, "-")
	lenIds := len(userIds)
	if lenIds <= 1 {
		err = fmt.Errorf("Wrong Namespace format %v !", pod.Namespace)
		return
	}
	userId := userIds[lenIds-1]
	uid, err := strconv.Atoi(userId)
	if err != nil {
		return
	}
	groupLabel := pod.Labels[network.GroupedLabel]

	// TODO: too many ifs
	if !URLSet {
		err = fmt.Errorf("Please configure url for getting IPs!")
		return
	}
	location := ipLocation

	if pod.Labels["location"] != "" {
		location = pod.Labels["location"]
	}
	req := IpRequire{
		UserId: uid,
	}
	if groupLabel != "" {
		req.Group = groupLabel
	} else {
		// If groupLabel is added, we do NOT need location.
		req.Location = location
	}

	switch nets[1] {
	case "InnerNet":
		req.NetType = 1 // Production environment: 1, Debug env: 2
		if pod.Labels["isPrivate"] == "1" {
			req.IsPrivate = 1
			req.Zone = pod.Labels["zone"]
		}
	case "OuterNet":
		req.NetType = 3
	case "PrivateNet":
		req.NetType = 4
	}
	glog.V(6).Infof("%v Get IP Req: %v", pod.GenerateName, req)

	reqBytes, _ := json.Marshal(req)

	var ipResp IpResp
	// Retry 3 times in case of network error.
	// TODO: add UUID to ensure idempotence.
	for i := 0; i < 3; i++ {
		ipResp, err = GetIPMaskForPod(reqBytes)
		// code = 0 means connection error
		if err != nil {
			glog.Errorf("Failed to GetIPMaskForPod %v: %v.  Req: %v", pod.Name, err, req)
			// If code is 0, network fails so retry.
			if ipResp.Code != 0 {
				return
			}
		} else {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	ip = ipResp.Result.IP
	mask = ipResp.Result.Mask
	location = ipResp.Result.Location
	if ip == "" {
		glog.Errorf("ipResp: %v", ipResp)
		return
	}
	// Pass from labels to annotaions so Kubelet can handle
	if pod.Labels[network.ChangeGateway] == "true" {
		pod.Annotations[network.ChangeGateway] = "true"
	}
	pod.Annotations[network.IPAnnotationKey] = fmt.Sprintf("%s-%s", nets[0], ip)
	pod.Annotations[network.MaskAnnotationKey] = fmt.Sprintf("%s-%d", nets[0], mask)
	pod.Annotations[network.RoutesAnnotationKey] = strings.Join(ipResp.Result.Routes, ";")
	if location != "" {
		pod.Annotations["location"] = location
		if pod.Spec.NodeSelector == nil {
			pod.Spec.NodeSelector = make(map[string]string)
		}
		pod.Spec.NodeSelector["location"] = location
	}
	if pod.Labels["zone"] != "" {
		pod.Spec.NodeSelector["zone"] = pod.Labels["zone"]
	}
	glog.V(6).Infof("Get IP: %v, Mask: %v, ForPod: %v ", ip, mask, pod.ObjectMeta)
	return
}

func GetGroupedIpFromPod(pod *v1.Pod) (group, ip string) {
	group = pod.Labels[network.GroupedLabel]
	if ips := pod.Annotations[network.IPAnnotationKey]; ips != "" {
		ipArr := strings.Split(ips, "-")
		if len(ipArr) == 2 {
			ip = ipArr[1]
		}
	}
	return
}

func ReleaseIPForPod(pod *v1.Pod) error {
	if URLSet {
		if group, ip := GetGroupedIpFromPod(pod); ip != "" && ip != "none" && ip != "empty" {
			glog.Infof("Releasing IP %v for pod %v", ip, pod.ObjectMeta)
			err := ReleaseGroupedIP(pod.Namespace, group, ip)
			return err
		}
	}
	return nil
}

// ControllerExpectationsInterface is an interface that allows users to set and wait on expectations.
// Only abstracted out for testing.
// Warning: if using KeyFunc it is not safe to use a single ControllerExpectationsInterface with different
// types of controllers, because the keys might conflict across types.
type ControllerExpectationsInterface interface {
	GetExpectations(controllerKey string) (*ControlleeExpectations, bool, error)
	SatisfiedExpectations(controllerKey string) bool
	DeleteExpectations(controllerKey string)
	SetExpectations(controllerKey string, add, del int) error
	ExpectCreations(controllerKey string, adds int) error
	ExpectDeletions(controllerKey string, dels int) error
	CreationObserved(controllerKey string)
	DeletionObserved(controllerKey string)
	RaiseExpectations(controllerKey string, add, del int)
	LowerExpectations(controllerKey string, add, del int)
}

// ControllerExpectations is a cache mapping controllers to what they expect to see before being woken up for a sync.
type ControllerExpectations struct {
	cache.Store
}

// GetExpectations returns the ControlleeExpectations of the given controller.
func (r *ControllerExpectations) GetExpectations(controllerKey string) (*ControlleeExpectations, bool, error) {
	if exp, exists, err := r.GetByKey(controllerKey); err == nil && exists {
		return exp.(*ControlleeExpectations), true, nil
	} else {
		return nil, false, err
	}
}

// DeleteExpectations deletes the expectations of the given controller from the TTLStore.
func (r *ControllerExpectations) DeleteExpectations(controllerKey string) {
	if exp, exists, err := r.GetByKey(controllerKey); err == nil && exists {
		if err := r.Delete(exp); err != nil {
			glog.V(2).Infof("Error deleting expectations for controller %v: %v", controllerKey, err)
		}
	}
}

// SatisfiedExpectations returns true if the required adds/dels for the given controller have been observed.
// Add/del counts are established by the controller at sync time, and updated as controllees are observed by the controller
// manager.
func (r *ControllerExpectations) SatisfiedExpectations(controllerKey string) bool {
	if exp, exists, err := r.GetExpectations(controllerKey); exists {
		if exp.Fulfilled() {
			return true
		} else if exp.isExpired() {
			glog.V(4).Infof("Controller expectations expired %#v", exp)
			return true
		} else {
			glog.V(4).Infof("Controller still waiting on expectations %#v", exp)
			return false
		}
	} else if err != nil {
		glog.V(2).Infof("Error encountered while checking expectations %#v, forcing sync", err)
	} else {
		// When a new controller is created, it doesn't have expectations.
		// When it doesn't see expected watch events for > TTL, the expectations expire.
		//	- In this case it wakes up, creates/deletes controllees, and sets expectations again.
		// When it has satisfied expectations and no controllees need to be created/destroyed > TTL, the expectations expire.
		//	- In this case it continues without setting expectations till it needs to create/delete controllees.
		glog.V(4).Infof("Controller %v either never recorded expectations, or the ttl expired.", controllerKey)
	}
	// Trigger a sync if we either encountered and error (which shouldn't happen since we're
	// getting from local store) or this controller hasn't established expectations.
	return true
}

// TODO: Extend ExpirationCache to support explicit expiration.
// TODO: Make this possible to disable in tests.
// TODO: Support injection of clock.
func (exp *ControlleeExpectations) isExpired() bool {
	return clock.RealClock{}.Since(exp.timestamp) > ExpectationsTimeout
}

// SetExpectations registers new expectations for the given controller. Forgets existing expectations.
func (r *ControllerExpectations) SetExpectations(controllerKey string, add, del int) error {
	exp := &ControlleeExpectations{add: int64(add), del: int64(del), key: controllerKey, timestamp: clock.RealClock{}.Now()}
	glog.V(4).Infof("Setting expectations %#v", exp)
	return r.Add(exp)
}

func (r *ControllerExpectations) ExpectCreations(controllerKey string, adds int) error {
	return r.SetExpectations(controllerKey, adds, 0)
}

func (r *ControllerExpectations) ExpectDeletions(controllerKey string, dels int) error {
	return r.SetExpectations(controllerKey, 0, dels)
}

// Decrements the expectation counts of the given controller.
func (r *ControllerExpectations) LowerExpectations(controllerKey string, add, del int) {
	if exp, exists, err := r.GetExpectations(controllerKey); err == nil && exists {
		exp.Add(int64(-add), int64(-del))
		// The expectations might've been modified since the update on the previous line.
		glog.V(4).Infof("Lowered expectations %#v", exp)
	}
}

// Increments the expectation counts of the given controller.
func (r *ControllerExpectations) RaiseExpectations(controllerKey string, add, del int) {
	if exp, exists, err := r.GetExpectations(controllerKey); err == nil && exists {
		exp.Add(int64(add), int64(del))
		// The expectations might've been modified since the update on the previous line.
		glog.V(4).Infof("Raised expectations %#v", exp)
	}
}

// CreationObserved atomically decrements the `add` expectation count of the given controller.
func (r *ControllerExpectations) CreationObserved(controllerKey string) {
	r.LowerExpectations(controllerKey, 1, 0)
}

// DeletionObserved atomically decrements the `del` expectation count of the given controller.
func (r *ControllerExpectations) DeletionObserved(controllerKey string) {
	r.LowerExpectations(controllerKey, 0, 1)
}

// Expectations are either fulfilled, or expire naturally.
type Expectations interface {
	Fulfilled() bool
}

// ControlleeExpectations track controllee creates/deletes.
type ControlleeExpectations struct {
	// Important: Since these two int64 fields are using sync/atomic, they have to be at the top of the struct due to a bug on 32-bit platforms
	// See: https://golang.org/pkg/sync/atomic/ for more information
	add       int64
	del       int64
	key       string
	timestamp time.Time
}

// Add increments the add and del counters.
func (e *ControlleeExpectations) Add(add, del int64) {
	atomic.AddInt64(&e.add, add)
	atomic.AddInt64(&e.del, del)
}

// Fulfilled returns true if this expectation has been fulfilled.
func (e *ControlleeExpectations) Fulfilled() bool {
	// TODO: think about why this line being atomic doesn't matter
	return atomic.LoadInt64(&e.add) <= 0 && atomic.LoadInt64(&e.del) <= 0
}

// GetExpectations returns the add and del expectations of the controllee.
func (e *ControlleeExpectations) GetExpectations() (int64, int64) {
	return atomic.LoadInt64(&e.add), atomic.LoadInt64(&e.del)
}

// NewControllerExpectations returns a store for ControllerExpectations.
func NewControllerExpectations() *ControllerExpectations {
	return &ControllerExpectations{cache.NewStore(ExpKeyFunc)}
}

// UIDSetKeyFunc to parse out the key from a UIDSet.
var UIDSetKeyFunc = func(obj interface{}) (string, error) {
	if u, ok := obj.(*UIDSet); ok {
		return u.key, nil
	}
	return "", fmt.Errorf("Could not find key for obj %#v", obj)
}

// UIDSet holds a key and a set of UIDs. Used by the
// UIDTrackingControllerExpectations to remember which UID it has seen/still
// waiting for.
type UIDSet struct {
	sets.String
	key string
}

// UIDTrackingControllerExpectations tracks the UID of the pods it deletes.
// This cache is needed over plain old expectations to safely handle graceful
// deletion. The desired behavior is to treat an update that sets the
// DeletionTimestamp on an object as a delete. To do so consistenly, one needs
// to remember the expected deletes so they aren't double counted.
// TODO: Track creates as well (#22599)
type UIDTrackingControllerExpectations struct {
	ControllerExpectationsInterface
	// TODO: There is a much nicer way to do this that involves a single store,
	// a lock per entry, and a ControlleeExpectationsInterface type.
	uidStoreLock sync.Mutex
	// Store used for the UIDs associated with any expectation tracked via the
	// ControllerExpectationsInterface.
	uidStore cache.Store
}

// GetUIDs is a convenience method to avoid exposing the set of expected uids.
// The returned set is not thread safe, all modifications must be made holding
// the uidStoreLock.
func (u *UIDTrackingControllerExpectations) GetUIDs(controllerKey string) sets.String {
	if uid, exists, err := u.uidStore.GetByKey(controllerKey); err == nil && exists {
		return uid.(*UIDSet).String
	}
	return nil
}

// ExpectDeletions records expectations for the given deleteKeys, against the given controller.
func (u *UIDTrackingControllerExpectations) ExpectDeletions(rcKey string, deletedKeys []string) error {
	u.uidStoreLock.Lock()
	defer u.uidStoreLock.Unlock()

	if existing := u.GetUIDs(rcKey); existing != nil && existing.Len() != 0 {
		glog.Errorf("Clobbering existing delete keys: %+v", existing)
	}
	expectedUIDs := sets.NewString()
	for _, k := range deletedKeys {
		expectedUIDs.Insert(k)
	}
	glog.V(4).Infof("Controller %v waiting on deletions for: %+v", rcKey, deletedKeys)
	if err := u.uidStore.Add(&UIDSet{expectedUIDs, rcKey}); err != nil {
		return err
	}
	return u.ControllerExpectationsInterface.ExpectDeletions(rcKey, expectedUIDs.Len())
}

// DeletionObserved records the given deleteKey as a deletion, for the given rc.
func (u *UIDTrackingControllerExpectations) DeletionObserved(rcKey, deleteKey string) {
	u.uidStoreLock.Lock()
	defer u.uidStoreLock.Unlock()

	uids := u.GetUIDs(rcKey)
	if uids != nil && uids.Has(deleteKey) {
		glog.V(4).Infof("Controller %v received delete for pod %v", rcKey, deleteKey)
		u.ControllerExpectationsInterface.DeletionObserved(rcKey)
		uids.Delete(deleteKey)
	}
}

// DeleteExpectations deletes the UID set and invokes DeleteExpectations on the
// underlying ControllerExpectationsInterface.
func (u *UIDTrackingControllerExpectations) DeleteExpectations(rcKey string) {
	u.uidStoreLock.Lock()
	defer u.uidStoreLock.Unlock()

	u.ControllerExpectationsInterface.DeleteExpectations(rcKey)
	if uidExp, exists, err := u.uidStore.GetByKey(rcKey); err == nil && exists {
		if err := u.uidStore.Delete(uidExp); err != nil {
			glog.V(2).Infof("Error deleting uid expectations for controller %v: %v", rcKey, err)
		}
	}
}

// NewUIDTrackingControllerExpectations returns a wrapper around
// ControllerExpectations that is aware of deleteKeys.
func NewUIDTrackingControllerExpectations(ce ControllerExpectationsInterface) *UIDTrackingControllerExpectations {
	return &UIDTrackingControllerExpectations{ControllerExpectationsInterface: ce, uidStore: cache.NewStore(UIDSetKeyFunc)}
}

// Reasons for pod events
const (
	// FailedCreatePodReason is added in an event and in a replica set condition
	// when a pod for a replica set is failed to be created.
	FailedCreatePodReason = "FailedCreate"
	// SuccessfulCreatePodReason is added in an event when a pod for a replica set
	// is successfully created.
	SuccessfulCreatePodReason = "SuccessfulCreate"
	// FailedDeletePodReason is added in an event and in a replica set condition
	// when a pod for a replica set is failed to be deleted.
	FailedDeletePodReason = "FailedDelete"
	// SuccessfulDeletePodReason is added in an event when a pod for a replica set
	// is successfully deleted.
	SuccessfulDeletePodReason = "SuccessfulDelete"
)

// RSControlInterface is an interface that knows how to add or delete
// ReplicaSets, as well as increment or decrement them. It is used
// by the deployment controller to ease testing of actions that it takes.
type RSControlInterface interface {
	PatchReplicaSet(namespace, name string, data []byte) error
}

// RealRSControl is the default implementation of RSControllerInterface.
type RealRSControl struct {
	KubeClient clientset.Interface
	Recorder   record.EventRecorder
}

var _ RSControlInterface = &RealRSControl{}

func (r RealRSControl) PatchReplicaSet(namespace, name string, data []byte) error {
	_, err := r.KubeClient.Extensions().ReplicaSets(namespace).Patch(name, types.StrategicMergePatchType, data)
	return err
}

// PodControlInterface is an interface that knows how to add or delete pods
// created as an interface to allow testing.
type PodControlInterface interface {
	// CreatePods creates new pods according to the spec.
	CreatePods(namespace string, template *v1.PodTemplateSpec, object runtime.Object) error
	// CreatePodsOnNode creates a new pod according to the spec on the specified node,
	// and sets the ControllerRef.
	CreatePodsOnNode(nodeName, namespace string, template *v1.PodTemplateSpec, object runtime.Object, controllerRef *metav1.OwnerReference) error
	// CreatePodsWithControllerRef creates new pods according to the spec, and sets object as the pod's controller.
	CreatePodsWithControllerRef(namespace string, template *v1.PodTemplateSpec, object runtime.Object, controllerRef *metav1.OwnerReference) error
	// DeletePod deletes the pod identified by podID.
	DeletePod(namespace string, podID string, object runtime.Object) error
	// PatchPod patches the pod.
	PatchPod(namespace, name string, data []byte) error
	// GetPod get the pod according to the namespace and podName.
	GetPod(namespace string, podName string) (*v1.Pod, error)
}

// RealPodControl is the default implementation of PodControlInterface.
type RealPodControl struct {
	KubeClient clientset.Interface
	Recorder   record.EventRecorder
}

var _ PodControlInterface = &RealPodControl{}

func getPodsLabelSet(template *v1.PodTemplateSpec) labels.Set {
	desiredLabels := make(labels.Set)
	for k, v := range template.Labels {
		desiredLabels[k] = v
	}
	return desiredLabels
}

func getPodsFinalizers(template *v1.PodTemplateSpec) []string {
	desiredFinalizers := make([]string, len(template.Finalizers))
	copy(desiredFinalizers, template.Finalizers)
	return desiredFinalizers
}

func getPodsAnnotationSet(template *v1.PodTemplateSpec, object runtime.Object) (labels.Set, error) {
	desiredAnnotations := make(labels.Set)
	for k, v := range template.Annotations {
		desiredAnnotations[k] = v
	}
	createdByRef, err := v1.GetReference(api.Scheme, object)
	if err != nil {
		return desiredAnnotations, fmt.Errorf("unable to get controller reference: %v", err)
	}

	// TODO: this code was not safe previously - as soon as new code came along that switched to v2, old clients
	//   would be broken upon reading it. This is explicitly hardcoded to v1 to guarantee predictable deployment.
	//   We need to consistently handle this case of annotation versioning.
	codec := api.Codecs.LegacyCodec(schema.GroupVersion{Group: v1.GroupName, Version: "v1"})

	createdByRefJson, err := runtime.Encode(codec, &v1.SerializedReference{
		Reference: *createdByRef,
	})
	if err != nil {
		return desiredAnnotations, fmt.Errorf("unable to serialize controller reference: %v", err)
	}
	desiredAnnotations[v1.CreatedByAnnotation] = string(createdByRefJson)
	return desiredAnnotations, nil
}

func getPodsPrefix(controllerName string) string {
	// use the dash (if the name isn't too long) to make the pod name a bit prettier
	prefix := fmt.Sprintf("%s-", controllerName)
	if len(validation.ValidatePodName(prefix, true)) != 0 {
		prefix = controllerName
	}
	return prefix
}

func validateControllerRef(controllerRef *metav1.OwnerReference) error {
	if controllerRef == nil {
		return fmt.Errorf("controllerRef is nil")
	}
	if len(controllerRef.APIVersion) == 0 {
		return fmt.Errorf("controllerRef has empty APIVersion")
	}
	if len(controllerRef.Kind) == 0 {
		return fmt.Errorf("controllerRef has empty Kind")
	}
	if controllerRef.Controller == nil || *controllerRef.Controller != true {
		return fmt.Errorf("controllerRef.Controller is not set to true")
	}
	if controllerRef.BlockOwnerDeletion == nil || *controllerRef.BlockOwnerDeletion != true {
		return fmt.Errorf("controllerRef.BlockOwnerDeletion is not set")
	}
	return nil
}

func (r RealPodControl) CreatePods(namespace string, template *v1.PodTemplateSpec, object runtime.Object) error {
	return r.createPods("", namespace, template, object, nil)
}

func (r RealPodControl) CreatePodsWithControllerRef(namespace string, template *v1.PodTemplateSpec, controllerObject runtime.Object, controllerRef *metav1.OwnerReference) error {
	if err := validateControllerRef(controllerRef); err != nil {
		return err
	}
	return r.createPods("", namespace, template, controllerObject, controllerRef)
}

func (r RealPodControl) CreatePodsOnNode(nodeName, namespace string, template *v1.PodTemplateSpec, object runtime.Object, controllerRef *metav1.OwnerReference) error {
	if err := validateControllerRef(controllerRef); err != nil {
		return err
	}
	return r.createPods(nodeName, namespace, template, object, controllerRef)
}

func (r RealPodControl) PatchPod(namespace, name string, data []byte) error {
	_, err := r.KubeClient.Core().Pods(namespace).Patch(name, types.StrategicMergePatchType, data)
	return err
}

func GetPodFromTemplate(template *v1.PodTemplateSpec, parentObject runtime.Object, controllerRef *metav1.OwnerReference) (*v1.Pod, error) {
	desiredLabels := getPodsLabelSet(template)
	desiredFinalizers := getPodsFinalizers(template)
	desiredAnnotations, err := getPodsAnnotationSet(template, parentObject)
	if err != nil {
		return nil, err
	}
	accessor, err := meta.Accessor(parentObject)
	if err != nil {
		return nil, fmt.Errorf("parentObject does not have ObjectMeta, %v", err)
	}
	prefix := getPodsPrefix(accessor.GetName())

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels:       desiredLabels,
			Annotations:  desiredAnnotations,
			GenerateName: prefix,
			Finalizers:   desiredFinalizers,
		},
	}
	if controllerRef != nil {
		pod.OwnerReferences = append(pod.OwnerReferences, *controllerRef)
	}
	clone, err := api.Scheme.DeepCopy(&template.Spec)
	if err != nil {
		return nil, err
	}
	pod.Spec = *clone.(*v1.PodSpec)
	return pod, nil
}

func (r RealPodControl) createPods(nodeName, namespace string, template *v1.PodTemplateSpec, object runtime.Object, controllerRef *metav1.OwnerReference) error {
	pod, err := GetPodFromTemplate(template, object, controllerRef)
	if err != nil {
		return err
	}
	// Get macvlan IP for grouped pod.
	ip, _, err := AddIPMaskIfPodLabeled(pod, namespace)
	if err != nil {
		glog.Errorf("Failed to add ip and mask for pod %v: %v", pod.Name, err)
	}

	if len(nodeName) != 0 {
		pod.Spec.NodeName = nodeName
	}
	if labels.Set(pod.Labels).AsSelectorPreValidated().Empty() {
		return fmt.Errorf("unable to create pods, no labels")
	}
	if newPod, err := r.KubeClient.Core().Pods(namespace).Create(pod); err != nil {
		r.Recorder.Eventf(object, v1.EventTypeWarning, FailedCreatePodReason, "Error creating: %v", err)
		// Release IP for grouped pod.
		if ip != "" {
			releaseErr := ReleaseGroupedIP(pod.Namespace, pod.Labels[network.GroupedLabel], ip)
			glog.Warningf("Releasing IP because creating pod %v failed: releaseErr:%v", pod.Name, releaseErr)
		}
		return fmt.Errorf("unable to create pods: %v", err)
	} else {
		accessor, err := meta.Accessor(object)
		if err != nil {
			glog.Errorf("parentObject does not have ObjectMeta, %v", err)
			return nil
		}
		glog.V(4).Infof("Controller %v created pod %v", accessor.GetName(), newPod.Name)
		switch controllerRef.Kind {
		case "ReplicationController":
			util.RecordRCPodEvent(r.Recorder, controllerRef.Name, newPod.Namespace, newPod.Name, "RcPodAdd", "RcPodAdd")
		case "Job":
			util.RecordJobPodEvent(r.Recorder, controllerRef.Name, newPod.Namespace, newPod.Name, "JobPodAdd", "JobPodAdd")
		}

		r.Recorder.Eventf(object, v1.EventTypeNormal, SuccessfulCreatePodReason, "Created pod: %v", newPod.Name)
	}
	return nil
}

func (r RealPodControl) DeletePod(namespace string, podID string, object runtime.Object) error {
	accessor, err := meta.Accessor(object)
	if err != nil {
		return fmt.Errorf("object does not have ObjectMeta, %v", err)
	}
	pod, err := r.KubeClient.Core().Pods(namespace).Get(podID, metav1.GetOptions{})
	if err != nil {
		glog.V(2).Infof("Controller %v get pod %v/%v Failed", accessor.GetName(), namespace, podID)
		pod = nil
	}
	glog.V(2).Infof("Controller %v deleting pod %v/%v", accessor.GetName(), namespace, podID)
	if err := r.KubeClient.Core().Pods(namespace).Delete(podID, nil); err != nil {
		r.Recorder.Eventf(object, v1.EventTypeWarning, FailedDeletePodReason, "Error deleting: %v", err)
		return fmt.Errorf("unable to delete pods: %v", err)
	} else {
		if pod != nil && len(pod.OwnerReferences) > 0 {
			err := ReleaseIPForPod(pod)
			if err != nil {
				glog.Errorf("Failed to delete %v's IP: %v", pod.Name, err)
			}
			switch pod.OwnerReferences[0].Kind {
			case "ReplicationController":
				util.RecordRCPodEvent(r.Recorder, accessor.GetName(), namespace, podID, "RcPodDelete", "RcPodDelete")
			case "Job":
				util.RecordJobPodEvent(r.Recorder, accessor.GetName(), namespace, podID, "JobPodDelete", "JobPodDelete")
			}
			r.Recorder.Eventf(object, v1.EventTypeNormal, SuccessfulDeletePodReason, "Deleted pod: %v", podID)
		}
	}
	return nil
}

func (r RealPodControl) GetPod(namespace string, podName string) (*v1.Pod, error) {
	if namespace == "" || podName == "" {
		return nil, fmt.Errorf("param is error")
	}

	pod, err := r.KubeClient.Core().Pods(namespace).Get(podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get pod %s, due to %v", namespace+podName, err)
	}

	return pod, nil
}

type FakePodControl struct {
	sync.Mutex
	Templates      []v1.PodTemplateSpec
	ControllerRefs []metav1.OwnerReference
	DeletePodName  []string
	Patches        [][]byte
	Err            error
}

var _ PodControlInterface = &FakePodControl{}

func (f *FakePodControl) PatchPod(namespace, name string, data []byte) error {
	f.Lock()
	defer f.Unlock()
	f.Patches = append(f.Patches, data)
	if f.Err != nil {
		return f.Err
	}
	return nil
}

func (f *FakePodControl) GetPod(namespace string, podName string) (*v1.Pod, error) {
	return nil, fmt.Errorf("Fake Pod Control doesn't support GetPod()")
}

func (f *FakePodControl) CreatePods(namespace string, spec *v1.PodTemplateSpec, object runtime.Object) error {
	f.Lock()
	defer f.Unlock()
	f.Templates = append(f.Templates, *spec)
	if f.Err != nil {
		return f.Err
	}
	return nil
}

func (f *FakePodControl) CreatePodsWithControllerRef(namespace string, spec *v1.PodTemplateSpec, object runtime.Object, controllerRef *metav1.OwnerReference) error {
	f.Lock()
	defer f.Unlock()
	f.Templates = append(f.Templates, *spec)
	f.ControllerRefs = append(f.ControllerRefs, *controllerRef)
	if f.Err != nil {
		return f.Err
	}
	return nil
}

func (f *FakePodControl) CreatePodsOnNode(nodeName, namespace string, template *v1.PodTemplateSpec, object runtime.Object, controllerRef *metav1.OwnerReference) error {
	f.Lock()
	defer f.Unlock()
	f.Templates = append(f.Templates, *template)
	f.ControllerRefs = append(f.ControllerRefs, *controllerRef)
	if f.Err != nil {
		return f.Err
	}
	return nil
}

func (f *FakePodControl) DeletePod(namespace string, podID string, object runtime.Object) error {
	f.Lock()
	defer f.Unlock()
	f.DeletePodName = append(f.DeletePodName, podID)
	if f.Err != nil {
		return f.Err
	}
	return nil
}

func (f *FakePodControl) Clear() {
	f.Lock()
	defer f.Unlock()
	f.DeletePodName = []string{}
	f.Templates = []v1.PodTemplateSpec{}
	f.ControllerRefs = []metav1.OwnerReference{}
	f.Patches = [][]byte{}
}

// ByLogging allows custom sorting of pods so the best one can be picked for getting its logs.
type ByLogging []*v1.Pod

func (s ByLogging) Len() int      { return len(s) }
func (s ByLogging) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s ByLogging) Less(i, j int) bool {
	// 1. assigned < unassigned
	if s[i].Spec.NodeName != s[j].Spec.NodeName && (len(s[i].Spec.NodeName) == 0 || len(s[j].Spec.NodeName) == 0) {
		return len(s[i].Spec.NodeName) > 0
	}
	// 2. PodRunning < PodUnknown < PodPending
	m := map[v1.PodPhase]int{v1.PodRunning: 0, v1.PodUnknown: 1, v1.PodPending: 2}
	if m[s[i].Status.Phase] != m[s[j].Status.Phase] {
		return m[s[i].Status.Phase] < m[s[j].Status.Phase]
	}
	// 3. ready < not ready
	if v1.IsPodReady(s[i]) != v1.IsPodReady(s[j]) {
		return v1.IsPodReady(s[i])
	}
	// TODO: take availability into account when we push minReadySeconds information from deployment into pods,
	//       see https://github.com/kubernetes/kubernetes/issues/22065
	// 4. Been ready for more time < less time < empty time
	if v1.IsPodReady(s[i]) && v1.IsPodReady(s[j]) && !podReadyTime(s[i]).Equal(podReadyTime(s[j])) {
		return afterOrZero(podReadyTime(s[j]), podReadyTime(s[i]))
	}
	// 5. Pods with containers with higher restart counts < lower restart counts
	if maxContainerRestarts(s[i]) != maxContainerRestarts(s[j]) {
		return maxContainerRestarts(s[i]) > maxContainerRestarts(s[j])
	}
	// 6. older pods < newer pods < empty timestamp pods
	if !s[i].CreationTimestamp.Equal(s[j].CreationTimestamp) {
		return afterOrZero(s[j].CreationTimestamp, s[i].CreationTimestamp)
	}
	return false
}

// ActivePods type allows custom sorting of pods so a controller can pick the best ones to delete.
type ActivePods []*v1.Pod

func (s ActivePods) Len() int      { return len(s) }
func (s ActivePods) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s ActivePods) Less(i, j int) bool {
	// 1. Unassigned < assigned
	// If only one of the pods is unassigned, the unassigned one is smaller
	if s[i].Spec.NodeName != s[j].Spec.NodeName && (len(s[i].Spec.NodeName) == 0 || len(s[j].Spec.NodeName) == 0) {
		return len(s[i].Spec.NodeName) == 0
	}
	// 2. PodPending < PodUnknown < PodRunning
	m := map[v1.PodPhase]int{v1.PodPending: 0, v1.PodUnknown: 1, v1.PodRunning: 2}
	if m[s[i].Status.Phase] != m[s[j].Status.Phase] {
		return m[s[i].Status.Phase] < m[s[j].Status.Phase]
	}
	// 3. Not ready < ready
	// If only one of the pods is not ready, the not ready one is smaller
	if v1.IsPodReady(s[i]) != v1.IsPodReady(s[j]) {
		return !v1.IsPodReady(s[i])
	}
	// TODO: take availability into account when we push minReadySeconds information from deployment into pods,
	//       see https://github.com/kubernetes/kubernetes/issues/22065
	// 4. Been ready for empty time < less time < more time
	// If both pods are ready, the latest ready one is smaller
	if v1.IsPodReady(s[i]) && v1.IsPodReady(s[j]) && !podReadyTime(s[i]).Equal(podReadyTime(s[j])) {
		return afterOrZero(podReadyTime(s[i]), podReadyTime(s[j]))
	}
	// 5. Pods with containers with higher restart counts < lower restart counts
	if maxContainerRestarts(s[i]) != maxContainerRestarts(s[j]) {
		return maxContainerRestarts(s[i]) > maxContainerRestarts(s[j])
	}
	// 6. Empty creation time pods < newer pods < older pods
	if !s[i].CreationTimestamp.Equal(s[j].CreationTimestamp) {
		return afterOrZero(s[i].CreationTimestamp, s[j].CreationTimestamp)
	}
	return false
}

// afterOrZero checks if time t1 is after time t2; if one of them
// is zero, the zero time is seen as after non-zero time.
func afterOrZero(t1, t2 metav1.Time) bool {
	if t1.Time.IsZero() || t2.Time.IsZero() {
		return t1.Time.IsZero()
	}
	return t1.After(t2.Time)
}

func podReadyTime(pod *v1.Pod) metav1.Time {
	if v1.IsPodReady(pod) {
		for _, c := range pod.Status.Conditions {
			// we only care about pod ready conditions
			if c.Type == v1.PodReady && c.Status == v1.ConditionTrue {
				return c.LastTransitionTime
			}
		}
	}
	return metav1.Time{}
}

func maxContainerRestarts(pod *v1.Pod) int {
	maxRestarts := 0
	for _, c := range pod.Status.ContainerStatuses {
		maxRestarts = integer.IntMax(maxRestarts, int(c.RestartCount))
	}
	return maxRestarts
}

// FilterActivePods returns pods that have not terminated.
func FilterActivePods(pods []*v1.Pod) []*v1.Pod {
	var result []*v1.Pod
	for _, p := range pods {
		if IsPodActive(p) {
			result = append(result, p)
		} else {
			glog.V(4).Infof("Ignoring inactive pod %v/%v in state %v, deletion time %v",
				p.Namespace, p.Name, p.Status.Phase, p.DeletionTimestamp)
		}
	}
	return result
}

func IsPodActive(p *v1.Pod) bool {
	return v1.PodSucceeded != p.Status.Phase &&
		v1.PodFailed != p.Status.Phase &&
		p.DeletionTimestamp == nil
}

// FilterActiveReplicaSets returns replica sets that have (or at least ought to have) pods.
func FilterActiveReplicaSets(replicaSets []*extensions.ReplicaSet) []*extensions.ReplicaSet {
	activeFilter := func(rs *extensions.ReplicaSet) bool {
		return rs != nil && *(rs.Spec.Replicas) > 0
	}
	return FilterReplicaSets(replicaSets, activeFilter)
}

type filterRS func(rs *extensions.ReplicaSet) bool

// FilterReplicaSets returns replica sets that are filtered by filterFn (all returned ones should match filterFn).
func FilterReplicaSets(RSes []*extensions.ReplicaSet, filterFn filterRS) []*extensions.ReplicaSet {
	var filtered []*extensions.ReplicaSet
	for i := range RSes {
		if filterFn(RSes[i]) {
			filtered = append(filtered, RSes[i])
		}
	}
	return filtered
}

// PodKey returns a key unique to the given pod within a cluster.
// It's used so we consistently use the same key scheme in this module.
// It does exactly what cache.MetaNamespaceKeyFunc would have done
// except there's not possibility for error since we know the exact type.
func PodKey(pod *v1.Pod) string {
	return fmt.Sprintf("%v/%v", pod.Namespace, pod.Name)
}

// ControllersByCreationTimestamp sorts a list of ReplicationControllers by creation timestamp, using their names as a tie breaker.
type ControllersByCreationTimestamp []*v1.ReplicationController

func (o ControllersByCreationTimestamp) Len() int      { return len(o) }
func (o ControllersByCreationTimestamp) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o ControllersByCreationTimestamp) Less(i, j int) bool {
	if o[i].CreationTimestamp.Equal(o[j].CreationTimestamp) {
		return o[i].Name < o[j].Name
	}
	return o[i].CreationTimestamp.Before(o[j].CreationTimestamp)
}

// ReplicaSetsByCreationTimestamp sorts a list of ReplicaSet by creation timestamp, using their names as a tie breaker.
type ReplicaSetsByCreationTimestamp []*extensions.ReplicaSet

func (o ReplicaSetsByCreationTimestamp) Len() int      { return len(o) }
func (o ReplicaSetsByCreationTimestamp) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o ReplicaSetsByCreationTimestamp) Less(i, j int) bool {
	if o[i].CreationTimestamp.Equal(o[j].CreationTimestamp) {
		return o[i].Name < o[j].Name
	}
	return o[i].CreationTimestamp.Before(o[j].CreationTimestamp)
}

// ReplicaSetsBySizeOlder sorts a list of ReplicaSet by size in descending order, using their creation timestamp or name as a tie breaker.
// By using the creation timestamp, this sorts from old to new replica sets.
type ReplicaSetsBySizeOlder []*extensions.ReplicaSet

func (o ReplicaSetsBySizeOlder) Len() int      { return len(o) }
func (o ReplicaSetsBySizeOlder) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o ReplicaSetsBySizeOlder) Less(i, j int) bool {
	if *(o[i].Spec.Replicas) == *(o[j].Spec.Replicas) {
		return ReplicaSetsByCreationTimestamp(o).Less(i, j)
	}
	return *(o[i].Spec.Replicas) > *(o[j].Spec.Replicas)
}

// ReplicaSetsBySizeNewer sorts a list of ReplicaSet by size in descending order, using their creation timestamp or name as a tie breaker.
// By using the creation timestamp, this sorts from new to old replica sets.
type ReplicaSetsBySizeNewer []*extensions.ReplicaSet

func (o ReplicaSetsBySizeNewer) Len() int      { return len(o) }
func (o ReplicaSetsBySizeNewer) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o ReplicaSetsBySizeNewer) Less(i, j int) bool {
	if *(o[i].Spec.Replicas) == *(o[j].Spec.Replicas) {
		return ReplicaSetsByCreationTimestamp(o).Less(j, i)
	}
	return *(o[i].Spec.Replicas) > *(o[j].Spec.Replicas)
}

func AddOrUpdateTaintOnNode(c clientset.Interface, nodeName string, taint *v1.Taint) error {
	firstTry := true
	return clientretry.RetryOnConflict(UpdateTaintBackoff, func() error {
		var err error
		var oldNode *v1.Node
		// First we try getting node from the API server cache, as it's cheaper. If it fails
		// we get it from etcd to be sure to have fresh data.
		if firstTry {
			oldNode, err = c.Core().Nodes().Get(nodeName, metav1.GetOptions{ResourceVersion: "0"})
			firstTry = false
		} else {
			oldNode, err = c.Core().Nodes().Get(nodeName, metav1.GetOptions{})
		}
		if err != nil {
			return err
		}
		newNode, ok, err := v1.AddOrUpdateTaint(oldNode, taint)
		if err != nil {
			return fmt.Errorf("Failed to update taint annotation!")
		}
		if !ok {
			return nil
		}
		return PatchNodeTaints(c, nodeName, oldNode, newNode)
	})
}

// RemoveTaintOffNode is for cleaning up taints temporarily added to node,
// won't fail if target taint doesn't exist or has been removed.
// If passed a node it'll check if there's anything to be done, if taint is not present it won't issue
// any API calls.
func RemoveTaintOffNode(c clientset.Interface, nodeName string, taint *v1.Taint, node *v1.Node) error {
	// Short circuit for limiting amout of API calls.
	if node != nil {
		match := false
		for i := range node.Spec.Taints {
			if node.Spec.Taints[i].MatchTaint(taint) {
				match = true
				break
			}
		}
		if !match {
			return nil
		}
	}
	firstTry := true
	return clientretry.RetryOnConflict(UpdateTaintBackoff, func() error {
		var err error
		var oldNode *v1.Node
		// First we try getting node from the API server cache, as it's cheaper. If it fails
		// we get it from etcd to be sure to have fresh data.
		if firstTry {
			oldNode, err = c.Core().Nodes().Get(nodeName, metav1.GetOptions{ResourceVersion: "0"})
			firstTry = false
		} else {
			oldNode, err = c.Core().Nodes().Get(nodeName, metav1.GetOptions{})
		}
		if err != nil {
			return err
		}
		newNode, ok, err := v1.RemoveTaint(oldNode, taint)
		if err != nil {
			return fmt.Errorf("Failed to update taint annotation!")
		}
		if !ok {
			return nil
		}
		return PatchNodeTaints(c, nodeName, oldNode, newNode)
	})
}

// PatchNodeTaints patches node's taints.
func PatchNodeTaints(c clientset.Interface, nodeName string, oldNode *v1.Node, newNode *v1.Node) error {
	oldData, err := json.Marshal(oldNode)
	if err != nil {
		return fmt.Errorf("failed to marshal old node %#v for node %q: %v", oldNode, nodeName, err)
	}

	newTaints := newNode.Spec.Taints
	objCopy, err := api.Scheme.DeepCopy(oldNode)
	if err != nil {
		return fmt.Errorf("failed to copy node object %#v: %v", oldNode, err)
	}
	newNode, ok := (objCopy).(*v1.Node)
	if !ok {
		return fmt.Errorf("failed to cast copy onto node object %#v: %v", newNode, err)
	}
	newNode.Spec.Taints = newTaints
	newData, err := json.Marshal(newNode)
	if err != nil {
		return fmt.Errorf("failed to marshal new node %#v for node %q: %v", newNode, nodeName, err)
	}

	patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldData, newData, v1.Node{})
	if err != nil {
		return fmt.Errorf("failed to create patch for node %q: %v", nodeName, err)
	}

	_, err = c.Core().Nodes().Patch(string(nodeName), types.StrategicMergePatchType, patchBytes)
	return err
}
