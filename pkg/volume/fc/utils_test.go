package fc

import (
	"testing"
	"fmt"
	"net/http/httptest"
	"net/http"
	"encoding/json"
	"time"
	"io/ioutil"
	"strconv"
)

func Test1(t *testing.T) {
	a1 := `{
	        "code":"200",
	        "message":"OK",
	        "result":{
	                  "fc":{
	                           "lun":1,
	                           "targetWWNs":["5000d31000d88233","5000d31000d88234","5000d31000d88232","5000d31000d88231"]
	                        },
	                  "name":  "bbb749b7-9062-4f8a-b518-dc837bc15ef7"
	                 }
	       }`

	a2 := `{
		"code":"200",
		"message":"OK",
		"result":{
			        "volid":"bbb749b7-9062-4f8a-b518-dc837bc15ef7",
				"volume":"fc",
				"owner":"32556",
				"size":25,
				"used_size":10,
				"status":"idle",
				"attach_status":"attached",
				"vol_type":"dellsc",
				"provider_misc":"",
				"create_time":"2018-03-20 14:44:19",
				"update_time":"2018-03-26 10:13:35",
				"volume_mapping":{
					"format":"ext4",
					"access_mode":"ReadWriteOnce",
					"path":null,
					"instance":"10.6.5.205",
					"mapping_misc": "xxx"
				}
			}
		}`

	result1 := VolumeInfo{}
	result2 := VolumeInfo{}

	json.Unmarshal([]byte(a1), &result1)
	fmt.Println(string(strconv.Itoa(result1.Result.FC.Lun)))

	json.Unmarshal([]byte(a2), &result2)
	fmt.Println(result2)
	fmt.Println(result2.Result)
	fmt.Println(result2.Result.Status, result2.Result.Attach_Status)
}

func TestLockToPod(t *testing.T) {
	volumeName1 := "aaaaaa"
	pod1 := "1"
	volumeName2 := "bbbbbb"
	pod2 := "2"
	volumeName3 := "cccccc"
	pod3 := "3"
	testHttpServce := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
		if r.Method != "POST" {
			w.WriteHeader(400)
		}
		if r.RequestURI == "/v1/volume/lock" {
			requestBody := map[string]string{}
			rawBody, _ := ioutil.ReadAll(r.Body)
			json.Unmarshal(rawBody, &requestBody)
			if requestBody["id"] == volumeName1 && requestBody["locker"] == pod1 {
				w.WriteHeader(200)
				return
			}
			if requestBody["id"] == volumeName2 && requestBody["locker"] == pod2 {
				w.WriteHeader(400)
				return
			}
			if requestBody["id"] == volumeName3 && requestBody["locker"] == pod3 {
				time.Sleep( 10 * time.Second)
				w.WriteHeader(200)
				return
			}
		}
	}))
	defer testHttpServce.Close()
	remoteVolumeServerAddress := testHttpServce.URL
	err := LockToPod(remoteVolumeServerAddress, volumeName1, pod1)
	if err != nil {
		t.Fatal("Should Success")
	}

	err = LockToPod(remoteVolumeServerAddress, volumeName2, pod2)
	if err == nil {
		t.Fatal("Should Fail")
	}

	err = LockToPod(remoteVolumeServerAddress, volumeName3, pod3)
	if err == nil {
		t.Fatal("Should Fail")
	}
}

func TestUnlockFromPod(t *testing.T) {
	volumeName1 := "aaaaaa"
	pod1 := "1"
	volumeName2 := "bbbbbb"
	pod2 := "2"
	volumeName3 := "cccccc"
	pod3 := "3"
	testHttpServce := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
		if r.Method != "POST" {
			w.WriteHeader(400)
		}
		if r.RequestURI == "/v1/volume/unlock" {
			requestBody := map[string]string{}
			rawBody, _ := ioutil.ReadAll(r.Body)
			json.Unmarshal(rawBody, &requestBody)
			if requestBody["id"] == volumeName1 && requestBody["locker"] == pod1 {
				w.WriteHeader(200)
				return
			}
			if requestBody["id"] == volumeName2 && requestBody["locker"] == pod2 {
				w.WriteHeader(400)
				return
			}
			if requestBody["id"] == volumeName3 && requestBody["locker"] == pod3 {
				time.Sleep( 10 * time.Second)
				w.WriteHeader(200)
				return
			}
		}
	}))
	defer testHttpServce.Close()
	remoteVolumeServerAddress := testHttpServce.URL
	err := UnlockFromPod(remoteVolumeServerAddress, volumeName1, pod1)
	if err != nil {
		t.Fatal("Should Success")
	}

	err = UnlockFromPod(remoteVolumeServerAddress, volumeName2, pod2)
	if err == nil {
		t.Fatal("Should Fail")
	}

	err = UnlockFromPod(remoteVolumeServerAddress, volumeName3, pod3)
	if err == nil {
		t.Fatal("Should Fail")
	}
}

func TestGetVolumeInfo(t *testing.T) {
	volumeName1 := "aaaaaa"
	volumeName2 := "bbbbbb"
	volumeName3 := "cccccc"
	volumeName4 := "dddddd"
	volumeName5 := "eeeeee"
	volumeName7 := "gggggg"
	volumeName8 := "hhhhhh"
	volumeName12 := "mmmmmm"
	testHttpServce := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
		if r.Method != "POST" {
			w.WriteHeader(400)
		}
		if r.RequestURI == ("/v1/volume/info?volid=" + volumeName1 ){
			data :=  VolumeInfo{}
			data.Result.Attach_Status = "attached"
			data.Result.Status = "busy"
			data.Result.Volume_Mapping.Instance = "node1"
			data.Result.Volume_Mapping.Mapping_Misc = "pod1"
			body,_ := json.Marshal(data)
			w.Write(body)
			w.WriteHeader(200)
			return
		}
		if r.RequestURI == ("/v1/volume/info?volid=" + volumeName2 ){
			data :=  VolumeInfo{}
			data.Result.Attach_Status = "attached"
			data.Result.Status = "idle"
			data.Result.Volume_Mapping.Instance = "node2"
			data.Result.Volume_Mapping.Mapping_Misc = "pod2"
			body,_ := json.Marshal(data)
			w.Write(body)
			w.WriteHeader(200)
			return
		}
		if r.RequestURI == ("/v1/volume/info?volid=" + volumeName3 ){
			data :=  VolumeInfo{}
			data.Result.Attach_Status = "detached"
			data.Result.Status = "idle"
			data.Result.Volume_Mapping.Instance = "node3"
			data.Result.Volume_Mapping.Mapping_Misc = "pod3"
			body,_ := json.Marshal(data)
			w.Write(body)
			w.WriteHeader(200)
			return
		}
		if r.RequestURI == ("/v1/volume/info?volid=" + volumeName4 ){
			data :=  VolumeInfo{}
			data.Result.Attach_Status = "detached"
			data.Result.Volume_Mapping.Instance = "node3"
			data.Result.Volume_Mapping.Mapping_Misc = "pod3"
			body,_ := json.Marshal(data)
			w.Write(body)
			w.WriteHeader(200)
			return
		}
		if r.RequestURI == ("/v1/volume/info?volid=" + volumeName5 ){
			data :=  VolumeInfo{}
			data.Result.Volume_Mapping.Instance = "node3"
			data.Result.Volume_Mapping.Mapping_Misc = "pod3"
			body,_ := json.Marshal(data)
			w.Write(body)
			w.WriteHeader(200)
			return
		}
		if r.RequestURI == ("/v1/volume/info?volid=" + volumeName7 ){
			data :=  VolumeInfo{}
			data.Result.Attach_Status = "detached"
			data.Result.Status = "idle"
			data.Result.Volume_Mapping.Instance = "node3"
			body,_ := json.Marshal(data)
			w.Write(body)
			w.WriteHeader(200)
			return
		}
		if r.RequestURI == ("/v1/volume/info?volid=" + volumeName7 ){
			data :=  VolumeInfo{}
			data.Result.Attach_Status = "detached"
			data.Result.Status = "idle"
			data.Result.Volume_Mapping.Instance = "node3"
			body,_ := json.Marshal(data)
			w.Write(body)
			w.WriteHeader(200)
			return
		}
		if r.RequestURI == ("/v1/volume/info?volid=" + volumeName8 ){
			data :=  VolumeInfo{}
			data.Result.Attach_Status = ""
			data.Result.Status = ""
			data.Result.Volume_Mapping.Instance = "node1"
			data.Result.Volume_Mapping.Mapping_Misc = "pod1"
			body,_ := json.Marshal(data)
			w.Write(body)
			w.WriteHeader(200)
			return
		}
		if r.RequestURI == ("/v1/volume/info?volid=" + volumeName12 ){
			time.Sleep(10 * time.Second)
			data :=  VolumeInfo{}
			data.Result.Attach_Status = "attached"
			data.Result.Status = "busy"
			data.Result.Volume_Mapping.Instance = "node1"
			data.Result.Volume_Mapping.Mapping_Misc = "pod1"
			body,_ := json.Marshal(data)
			w.Write(body)
			w.WriteHeader(200)
			return
		}
	}))
	defer testHttpServce.Close()
	remoteVolumeServerAddress := testHttpServce.URL

	attachToNode, lockedByPod, podID, nodeID, _, err := GetVolumeStatus(remoteVolumeServerAddress, volumeName1)

	if !attachToNode || !lockedByPod || podID != "pod1" || nodeID != "node1" || err != nil {
		t.Errorf("attachToNode: %v; lockedByPod: %v; podID: %v; nodeID: %v; err: %v", attachToNode, lockedByPod, podID, nodeID, err)
		t.Fatal("Should Success")
	}

	attachToNode, lockedByPod, podID, nodeID, _, err = GetVolumeStatus(remoteVolumeServerAddress, volumeName2)

	if !attachToNode || lockedByPod || podID != "pod2" || nodeID != "node2" || err != nil {
		t.Errorf("attachToNode: %v; lockedByPod: %v; podID: %v; nodeID: %v; err: %v", attachToNode, lockedByPod, podID, nodeID, err)
		t.Fatal("Should Success")
	}

	attachToNode, lockedByPod, podID, nodeID, _, err = GetVolumeStatus(remoteVolumeServerAddress, volumeName3)

	if attachToNode || lockedByPod || podID != "pod3" || nodeID != "node3" || err != nil {
		t.Errorf("attachToNode: %v; lockedByPod: %v; podID: %v; nodeID: %v; err: %v", attachToNode, lockedByPod, podID, nodeID, err)
		t.Fatal("Should Success")
	}

	attachToNode, lockedByPod, podID, nodeID, _,  err = GetVolumeStatus(remoteVolumeServerAddress, volumeName4)

	if  err == nil {
		t.Fatal("Should Fail")
	}

	attachToNode, lockedByPod, podID, nodeID, _, err = GetVolumeStatus(remoteVolumeServerAddress, volumeName5)

	if  err == nil {
		t.Fatal("Should Fail")
	}

	attachToNode, lockedByPod, podID, nodeID, _,  err = GetVolumeStatus(remoteVolumeServerAddress, volumeName7)

	if  err != nil || podID != "" {
		t.Fatal("podID should empty")
	}

	attachToNode, lockedByPod, podID, nodeID, _, err = GetVolumeStatus(remoteVolumeServerAddress, volumeName8)
	if err == nil {
		t.Errorf("attachToNode: %v; lockedByPod: %v; podID: %v; nodeID: %v; err: %v", attachToNode, lockedByPod, podID, nodeID, err)
		t.Fatal("Should Fail")
	}
	attachToNode, lockedByPod, podID, nodeID, _, err = GetVolumeStatus(remoteVolumeServerAddress, volumeName12)
	if err == nil {
		t.Errorf("attachToNode: %v; lockedByPod: %v; podID: %v; nodeID: %v; err: %v", attachToNode, lockedByPod, podID, nodeID, err)
		t.Fatal("Should Fail")
	}
}

func TestFCRemoteAttach(t *testing.T) {
	volumeName1 := "aaaaaa"
	volumeName2 := "bbbbbb"
	volumeName3 := "cccccc"
	volumeName4 := "dddddd"
	testHttpServce := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
		if r.Method != "POST" {
			w.WriteHeader(400)
		}
		if r.RequestURI == ("/v1/volume/attach/" + volumeName1 ){
			var data VolumeInfo
			data.Code = "200"
			data.Message = "OK"
			data.Result.FC.Lun = 1
			data.Result.FC.TargerWWNs = []string{"5000d31000d88233","5000d31000d88232","5000d31000d88234","5000d31000d88231"}
			body,_ := json.Marshal(data)
			w.Write(body)
			w.WriteHeader(200)
			return
		}
		if r.RequestURI == ("/v1/volume/attach/" + volumeName4 ){
			var data VolumeInfo
			data.Code = "200"
			data.Message = "OK"
			data.Result.FC.Lun = -1
			data.Result.FC.TargerWWNs = []string{"5000d31000d88233","5000d31000d88232","5000d31000d88234","5000d31000d88231"}
			body,_ := json.Marshal(data)
			w.Write(body)
			w.WriteHeader(200)
			return
		}
		if r.RequestURI == ("/v1/volume/attach/" + volumeName2 ){
			var data VolumeInfo
			data.Code = "433"
			data.Message = "{\"result\":\"StorageCenterError - Exception Message: Error creating a Mapping Profile: Server already mapped to volume\"}"
			body,_ := json.Marshal(data)
			w.WriteHeader(433)
			w.Write(body)
			return
		}
		if r.RequestURI == ("/v1/volume/attach/" + volumeName3 ){
			time.Sleep(10 * time.Second)
			var data VolumeInfo
			data.Code = "433"
			data.Message = "{\"result\":\"StorageCenterError - Exception Message: Error creating a Mapping Profile: Server already mapped to volume\"}"
			body,_ := json.Marshal(data)
			w.Write(body)
			w.WriteHeader(200)
			return
		}
	}))

	defer testHttpServce.Close()
	remoteVolumeServerAddress := testHttpServce.URL
	volName := volumeName1
	instanceID := "aaaaaa"
	_, _, err := FCAttachToServer(remoteVolumeServerAddress, volName, instanceID)
	if err != nil {
		t.Fatal("volume aaaaaa should succeed")
	}

	volName = volumeName2
	instanceID = "bbbbbb"
	_, _, err = FCAttachToServer(remoteVolumeServerAddress, volName, instanceID)
	if err == nil {
		t.Fatal("volume bbbbbb should fail")
	}

	volName = volumeName3
	instanceID = "cccccc"
	_, _, err = FCAttachToServer(remoteVolumeServerAddress, volName, instanceID)
	if err == nil {
		t.Fatal("volume ccccc should fail")
	}

	volName = volumeName4
	instanceID = "dddddd"
	_, _, err = FCAttachToServer(remoteVolumeServerAddress, volName, instanceID)
	if err == nil {
		t.Fatal("volume ddddddd should fail")
	}
}

func TestRemoteDetach(t *testing.T) {
	volumeName1 := "aaaaaa"
	volumeName2 := "bbbbbb"
	volumeName3 := "cccccc"
	testHttpServce := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
		if r.Method != "POST" {
			w.WriteHeader(400)
		}
		if r.RequestURI == ("/v1/volume/detach/" + volumeName1 ){
			var res VolumeInfo
			res.Code = "200"
			res.Message = "OK"
			res.Result.FC.Lun = 1
			res.Result.FC.TargerWWNs = []string{"5000d31000d88233","5000d31000d88232","5000d31000d88234","5000d31000d88231"}
			res.Result.Name = "aaaaaa"
			body,_ := json.Marshal(res)
			w.Write(body)
			w.WriteHeader(200)
			return
		}
		if r.RequestURI == ("/v1/volume/detach/" + volumeName2 ){
			var res VolumeInfo
			res.Code = "433"
			res.Message = "对应卷已解除映射"
			body,_ := json.Marshal(res)
			w.WriteHeader(433)
			w.Write(body)
			return
		}
		if r.RequestURI == ("/v1/volume/detach/" + volumeName3 ){
			time.Sleep(10*time.Second)
			var res VolumeInfo
			res.Code = "433"
			res.Message = "对应卷已解除映射"
			body,_ := json.Marshal(res)
			w.Write(body)
			w.WriteHeader(200)
			return
		}
	}))
	defer testHttpServce.Close()

	remoteVolumeServerAddress := testHttpServce.URL
	volName := volumeName1
	instanceID := "aaaaaa"
	err := DetachFromServer(remoteVolumeServerAddress, volName, instanceID)
	if err != nil {
		t.Fatal("volume aaaaaa should succeed")
	}

	volName = volumeName2
	instanceID = "bbbbbb"
	err = DetachFromServer(remoteVolumeServerAddress, volName, instanceID)
	if err == nil {
		t.Fatal("volume bbbbbb should fail")
	}

	volName = volumeName3
	instanceID = "cccccc"
	err = DetachFromServer(remoteVolumeServerAddress, volName, instanceID)
	if err == nil {
		t.Fatal("volume ccccc should fail")
	}
}
