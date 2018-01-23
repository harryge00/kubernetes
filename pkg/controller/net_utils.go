/*
Author: Haoyuan Ge
This file contains functions for getting/releasing IP for macvlan.
*/
package controller

import (
	"k8s.io/api/core/v1"

	"github.com/golang/glog"
	"bytes"
	"fmt"
	"net/http"
	"encoding/json"
	"io/ioutil"
	"strings"
	"strconv"
	"time"

)

// The consts below are Used for macvlan plugin
const (
	MaskAnnotationKey = "mask"
	IPAnnotationKey   = "ips"
	NetworkKey        = "network"
	// Label for network groups
	GroupedLabel = "networkgroup"
)

var (
	URLSet       = false
	baseIPURL    = "http://localhost:8080"
	getIPURL     = "http://localhost:8080/api/net/ip/occupy"
	releaseIPURL = "http://localhost:8080/api/net/ip/release"
	ipLocation   = "1199"
)
type IpResp struct {
	Result  IpResult `json:"result,omitempty"`
	Code    int      `json:"code,omitempty"`
	Message string   `json:"message,omitempty"`
}

type IpRequire struct {
	Group    string `json:"group,omitempty"`
	UserId   int    `json:"userId,omitempty"`
	NetType  int    `json:"type,omitempty"`
	Location string `json:"location,omitempty"`
}

type IpRelease struct {
	IP     string `json:"ip,omitempty"`
	Group  string `json:"group,omitempty"`
	UserId int    `json:"userId,omitempty"`
}

type IpResult struct {
	IP       string `json:"ip,omitempty"`
	Mask     int    `json:"mask,omitempty"`
	Occupied int    `json:"occupied,omitempty"`
	Location string `json:"location,omitempty"`
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

func GetIPMaskForPod(reqBytes []byte) (ip, location string, mask int, httpCode int, err error) {
	resp, err := http.Post(getIPURL, "application/json", bytes.NewBuffer(reqBytes))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	var ipResp IpResp
	err = json.Unmarshal(body, &ipResp)
	if err != nil {
		return
	}
	httpCode = ipResp.Code
	if httpCode != 200 {
		err = fmt.Errorf("%v", ipResp.Message)
		return
	}
	ip = ipResp.Result.IP
	mask = ipResp.Result.Mask
	location = ipResp.Result.Location
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
	return err
}

func AddIPMaskIfPodLabeled(pod *v1.Pod, namespace string) (ip string, mask int, err error) {
	// No needs to add ips if no label or "ips" has already been added.
	if pod.ObjectMeta.Annotations[IPAnnotationKey] != "" || pod.ObjectMeta.Labels[NetworkKey] == "" {
		return
	}
	nets := strings.Split(pod.ObjectMeta.Labels[NetworkKey], "-")
	if len(nets) != 2 {
		err = fmt.Errorf("Illegal network label: %v", pod.ObjectMeta.Labels[NetworkKey])
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
	groupLabel := pod.ObjectMeta.Labels[GroupedLabel]

	// TODO: too many ifs
	if !URLSet {
		err = fmt.Errorf("Please configure url for getting IPs!")
		return
	}
	req := IpRequire{
		UserId:   uid,
		Location: ipLocation,
	}
	if groupLabel != "" {
		req.Group = groupLabel
	}
	switch nets[1] {
	case "InnerNet":
		req.NetType = 1 // Production environment: 1, Debug env: 2
	case "OuterNet":
		req.NetType = 3
	}
	glog.V(6).Infof("Get IP req: %v", req)

	reqBytes, _ := json.Marshal(req)

	var code int
	var location string
	// Retry 3 times in case of network error.
	// TODO: add UUID to ensure idempotence.
	for i := 0; i < 3; i++ {
		ip, location, mask, code, err = GetIPMaskForPod(reqBytes)
		// code = 0 means connection error
		if err != nil {
			glog.Errorf("Failed to GetIPMaskForPod %v: %v.  Req: %v", pod.Name, err, req)
			// If code is 0, network fails so retry.
			if code != 0 {
				return
			}
		} else {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	pod.ObjectMeta.Annotations[IPAnnotationKey] = fmt.Sprintf("%s-%s", nets[0], ip)
	pod.ObjectMeta.Annotations[MaskAnnotationKey] = fmt.Sprintf("%s-%d", nets[0], mask)
	pod.ObjectMeta.Annotations[GroupedLabel] = pod.ObjectMeta.Labels[GroupedLabel]

	if location != "" {
		pod.ObjectMeta.Annotations["location"] = location
		if pod.Spec.NodeSelector == nil {
			pod.Spec.NodeSelector = make(map[string]string)
		}
		pod.Spec.NodeSelector["location"] = location
	}
	glog.V(6).Infof("Get IP: %v, Mask: %v, ForPod: %v ", ip, mask, pod.ObjectMeta)
	return
}

func GetGroupedIpFromPod(pod *v1.Pod) (group, ip string) {
	group = pod.ObjectMeta.Labels[GroupedLabel]
	if ips := pod.ObjectMeta.Annotations[IPAnnotationKey]; ips != "" {
		ipArr := strings.Split(ips, "-")
		if len(ipArr) == 2 {
			ip = ipArr[1]
		}
	}
	return
}

func ReleaseIPForAnnotations(namespace string, annotations map[string]string) error {
	if ips := annotations[IPAnnotationKey]; ips != "" {
		ipArr := strings.Split(ips, "-")
		if len(ipArr) == 2 {
			ip := ipArr[1]
			return ReleaseGroupedIP(namespace, annotations[GroupedLabel], ip)
		}
	}
	return nil
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
