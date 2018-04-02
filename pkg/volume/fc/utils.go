package fc

import (
	"fmt"
	"net/http"
	"time"
	"io/ioutil"
	"encoding/json"
	"bytes"
	"strconv"
	"github.com/golang/glog"
	"strings"
)

type Volume_Mapping struct {
	Format		string 		 `json:"format,omitempy"`
	Access_Mode     string 		 `json:"access_mode,omitempty"`
	Path            string		 `json:"path,omitempty"`
	Instance        string           `json:"instance,omitempty"`
	Mapping_Misc    string           `json:"mapping_misc,omitempty"`
}

type FC struct {
	Lun             int             `json:"lun"`
	TargerWWNs      []string        `json:"targetWWNs"`
}

type ISCSI struct {
	IQN		string 		`json:"iqn,omitempy"`
	Lun 		int		`json:"lun,omitempy"`
	TargetPortal    string		`json:"targetPortal,omitempy"`
}

type VolumeDetails struct {
	Volid           string 	        `json:"volid,omitempty"`
	Volume	        string		`json:"volume,omitempty"`
	Owner           string          `json:"owner,omitempty"`
	Size            uint64          `json:"size,omitempty"`
	Used_Size       uint64          `json:"used_size,omitempty"`
	Status          string          `json:"status,omitempty"`
	Attach_Status   string          `json:"attach_status,omitempty"`
	Vol_Type        string          `json:"vol_type,omitempty"`
	Provider_Misc   string          `json:"provider_misc,omitempty"`
	Name 		string 		`json:"name,omitempty"`
	FC 		FC              `json:"fc,omitempty"`
	ISCSI           []ISCSI         `json:"iscsi,omitempty"`
	Volume_Mapping  Volume_Mapping  `json:"volume_mapping,omitempty"`
}

type VolumeInfo struct {
	Code 		string 		`json:"code,omitempty"`
	Message 	string		`json:"message,omitempty"`
	Name		string 		`json:"name,omitempty"`
	Result          VolumeDetails   `json:"result,omitempty"`
}

func GetVolumeStatus(remoteServerAddress string, volumeName string) (attachedToNode bool, lockedByPod bool, podID string, nodeID string, provider_misc string, err error) {
	glog.V(1).Info("RemoteAttach/RemoteDetach Try To Get Volume Infomation")
	httpClient := http.Client{}
	httpClient.Timeout = 3 * time.Second
	requestUrl := remoteServerAddress + "/v1/volume/info?volid=" + volumeName
	response, err := httpClient.Get(requestUrl)
	if err != nil {
		err = fmt.Errorf("Unable To Get Volume: %v Infomation, Error is : %v", volumeName, err)
		return
	}

	var data VolumeInfo
	body, _ := ioutil.ReadAll(response.Body)
	if err = json.Unmarshal(body, &data); err != nil {
		err = fmt.Errorf("Invalid Volume Server Response, Can't Marshal it. Error is: %v", err)
		return
	}

	if data.Result.Attach_Status == "attached" {
		attachedToNode = true
	} else if data.Result.Attach_Status == "detached" {
		attachedToNode = false
	} else {
		err = fmt.Errorf("Invalid Volume Server Response, attach_status is Invalid, attach_status: %v", data.Result.Attach_Status)
		return
	}

	if data.Result.Status == "idle" {
		lockedByPod = false
	} else if data.Result.Status == "busy" {
		lockedByPod = true
	} else {
		err = fmt.Errorf("Invalid Volume Server Response, status is Invalid, status: %v", data.Result.Status)
		return
	}
	podID = data.Result.Volume_Mapping.Mapping_Misc
	nodeID = data.Result.Volume_Mapping.Instance
	provider_misc = data.Result.Provider_Misc
	return
}

func FCAttachToServer(remoteVolumeServerAddress, instanceID, volName string) (lun int, targetWWns []string, err error) {
	glog.V(1).Info("FibreChannel RemoteAttach Begin")
	glog.V(1).Info("RemoteAttach FibreChannel: " + instanceID + ";" + remoteVolumeServerAddress + ";" + volName)
	httpClient := http.Client{}
	httpClient.Timeout = 3 * time.Second
	requestUrl := remoteVolumeServerAddress + "/v1/volume/attach/" + volName
	glog.V(1).Info("RemoteAttach FibreChannel URL : " + requestUrl )
	requestData := "{\"instance\":\"" + instanceID  + "\",\"protocol\":\"FibreChannel\"}"
	glog.V(1).Info("RemoteAttach FibreChannel Body: " + string(requestData))

	response, err := httpClient.Post(requestUrl,"application/json", bytes.NewReader([]byte(requestData)))
	if err != nil {
		return
	}
	glog.V(1).Info("RemoteAttach FibreChannel Response : " ,  response.StatusCode, response.Header )
	var data VolumeInfo
	//var data map[string]interface{}
	body, _ := ioutil.ReadAll(response.Body)
	if err = json.Unmarshal(body, &data); err != nil {
		return
	}
	glog.V(1).Info("RemoteAttach FibreChannel ReturnBody: " , data)
	if response.StatusCode != 200 && response.StatusCode != 704 {
		err = fmt.Errorf(data.Message)
		return
	}

	if data.Result.FC.TargerWWNs == nil {
		err = fmt.Errorf("RemoteAttach FibreChannel ReturnBody Invalid: targetWWNs is nil!")
		return
	}

	lun = data.Result.FC.Lun
	if  lun < 0 {
		err = fmt.Errorf("RemoteAttach FibreChannel ReturnBody Invalid: lun < 0 ")
		return
	}
	targetWWns = data.Result.FC.TargerWWNs
	if len(targetWWns) == 0 {
		err = fmt.Errorf("RemoteAttach FibreChannel ReturnBody Invalid: len(targetWWns) == 0 ")
		return
	}
	glog.V(1).Info("RemoteAttach FibreChannel Success")
	glog.V(1).Infof("RemoteAttach FibreChannel Success: Lun=%v TargetWWNs=%v", lun, targetWWns)
	return lun, targetWWns , nil
}

func LockToPod(remoteVolumeServerAddress, volName, podID string) error {
	glog.V(1).Info("FibreChannel LockToPod Begin")
	glog.V(1).Info("FibreChannel LockToPod Infomation: PodID=%v VolumeServer=%v VolumeID=%v", podID, remoteVolumeServerAddress, volName)
	httpClient := http.Client{}
	httpClient.Timeout = 3 * time.Second
	requestUrl := remoteVolumeServerAddress + "/v1/volume/lock"
	requestData := "{\"id\":\"" + volName  + "\",\"locker\":\"" + podID + "\"}"
	glog.V(1).Info("FibreChannel LockToPod RequestInfo: %v", requestData)
	response, err := httpClient.Post(requestUrl,"application/json", bytes.NewReader([]byte(requestData)))
	if err != nil {
		return err
	}

	if response.StatusCode != 200 {
		glog.V(1).Info("FibreChannel LockToPod Failed: %v", requestData)
		return fmt.Errorf("VolumeID=%v PodID=%v LockToPod Failed", volName, podID)
	}
	glog.V(1).Info("FibreChannel LockToPod Success, VolumeID=%v", requestData)
	return nil
}


func DetachFromServer(remoteVolumeServerAddress, instanceID, volName string) error {
	glog.V(1).Info("FibreChannel RemoteDetach Begin")
	glog.V(1).Info("FibreChannel RemoteDetach FibreChannel: " + instanceID + ";" + remoteVolumeServerAddress + ";" + volName)
	httpClient := http.Client{}
	httpClient.Timeout = 3 * time.Second
	requestUrl := remoteVolumeServerAddress + "/v1/volume/detach/" + volName
	response, err := httpClient.Post(requestUrl,"application/json", bytes.NewReader([]byte("")))
	if err != nil {
		return err
	}
	var data VolumeInfo
	body, _ := ioutil.ReadAll(response.Body)
	if err := json.Unmarshal(body, &data); err != nil {
		return err
	}
	glog.V(1).Info("Dell RemoteDetach ReturnBody: " , data)
	if response.StatusCode != 200 && response.StatusCode != 705 {
		return fmt.Errorf(data.Message)
	}
	glog.V(1).Info("Dell RemoteDetach Success")
	return nil
}

func UnlockFromPod(remoteVolumeServerAddress, volName, podID string) error {
	glog.V(1).Info("FibreChannel UnlockFromPod Begin: VolumeID=%v PodID=%v", volName, podID)
	httpClient := http.Client{}
	httpClient.Timeout = 3 * time.Second
	requestUrl := remoteVolumeServerAddress + "/v1/volume/unlock"
	requestData := "{\"id\":\"" + volName  + "\",\"locker\":\"" + podID + "\"}"
	glog.V(1).Info("FibreChannel UnlockFromPod RequestContent: %v", requestData)
	response, err := httpClient.Post(requestUrl,"application/json", bytes.NewReader([]byte(requestData)))
	if err != nil {
		glog.V(1).Info("FibreChannel UnlockFromPod Failed: %v", err)
		return err
	}

	if response.StatusCode != 200 {
		glog.V(1).Info("FibreChannel UnlockFromPod Failed, RemoteServer Refuse")
		return fmt.Errorf("FibreChannel Unlock volume %v from pod: %v failed", volName, podID)
	}
	glog.V(1).Info("FibreChannel UnlockFromPod Success")
	return nil
}

//two Phase: 1. Unmap To Server; 2. Unlock from Pod
func Unlock(remoteVolumeServerAddress, volName, podID, instanceID string) error {
	glog.V(1).Info("FibreChannel Unlock Begin")
	glog.V(1).Info("FibreChannel Unlock, Try to UnlockFromPod Begin")
	err := UnlockFromPod(remoteVolumeServerAddress, volName, podID)
	if err != nil {
		glog.V(1).Info("FibreChannel Unlock, UnlockFromPod Failed: %v", err)
		return err
	}

	glog.V(1).Info("FibreChannel Unlock, Try to RemoteDetach from Server")
	err = DetachFromServer(remoteVolumeServerAddress, instanceID, volName)
	if err != nil {
		glog.V(1).Info("FibreChannel Unlock, RemoteDetach Failed: %v", err)
		return err
	}
	return nil
}

// If volume is not belong to Node and Pod, MapTo Node and LockTo Pod
// If volume is not belong to Node but belong to this Pod, Just MapTo this Node
// If volume is belong to this Node but not belong to this Pod, Return Fail
// If volume is belong to Node and belong to this Pod, Return Success
// If volume is not belong to Any pod, LockTo this Pod,Return Success
// If volume is not belong to Any Node, but Not belong to this Pod, return Fail
func LockFibreChannel(b *fcDiskMounter) (bool, error) {
	glog.V(1).Info("FibreChannel Lock Volume Begin")
	_, _, podID, nodeID, provide_misc,  err := GetVolumeStatus(b.remoteVolumeServerAddress, b.volName)
	if err != nil {
		glog.V(1).Info("FibreChannel Lock Volume Failed,Cause We Can't Get Information")
		return false,fmt.Errorf("FibreChannel Get Volume Info Error: %v",err)
	}

	if nodeID == "" {
		if podID == "" {
			glog.V(1).Info("FibreChannel Try To RemoteAttach")
			lun, targetWWns, err := FCAttachToServer(b.remoteVolumeServerAddress,b.instanceID, b.volName)
			if err != nil {
				glog.V(1).Info("FibreChannel RemoteAttach Failed %v", err)
				return false, err
			}

			b.fcDisk.lun = strconv.Itoa(lun)
			b.fcDisk.wwns = targetWWns
			glog.V(1).Info("FibreChannel Try To LockToPod")
			err = LockToPod(b.remoteVolumeServerAddress, b.volName, b.podID)
			if err != nil {
				glog.V(1).Info("FibreChannel LockToPod Failed")
				return false, err
			}
			return true, nil
		} else {
			return false, fmt.Errorf("Remote Server Locker Error: This Volume Belong to A Pod but not belong to a Node")
		}
	} else if nodeID != b.instanceID {
		if podID == "" {
			glog.V(1).Info("FibreChannel Try To RemoteDetach From Node: " + nodeID)
			err := DetachFromServer(b.remoteVolumeServerAddress, nodeID, b.volName)
			if err != nil {
				return false, fmt.Errorf("FibreChannel Volume belong to Node: %v, but not belong to Any Pod,We try release it then MapTo %v,Meet Error: %v", nodeID, b.instanceID, err)
			}
			glog.V(1).Info("FibreChannel Try To RemoteAttach")
			lun, targetWWns, err := FCAttachToServer(b.remoteVolumeServerAddress,b.instanceID, b.volName)
			if err != nil {
				glog.V(1).Info("FibreChannel RemoteAttach Failed %v", err)
				return false, err
			}

			b.fcDisk.lun = strconv.Itoa(lun)
			b.fcDisk.wwns = targetWWns
			glog.V(1).Info("FibreChannel Try To LockToPod")
			err = LockToPod(b.remoteVolumeServerAddress, b.volName, b.podID)
			if err != nil {
				glog.V(1).Info("FibreChannel LockToPod Failed")
				return false, err
			}
			return true, nil
		} else if podID != b.podID {
			return false, fmt.Errorf("FibreChannel Already Locked by another Pod: %v", podID)
		} else {
			// pod transfer to another node
			err := Unlock(b.remoteVolumeServerAddress, b.volName, b.podID , nodeID)
			if err != nil {
				return true, fmt.Errorf("FibreChannel Volume belong to Another Node, but belong to this Pod, Try Unlock Volume ,But Meet Error: %v", err)
			}

			glog.V(1).Info("FibreChannel Try To RemoteAttach")
			lun, targetWWns, err := FCAttachToServer(b.remoteVolumeServerAddress,b.instanceID, b.volName)
			if err != nil {
				glog.V(1).Info("FibreChannel RemoteAttach Failed %v", err)
				return false, err
			}

			b.fcDisk.lun = strconv.Itoa(lun)
			b.fcDisk.wwns = targetWWns
			glog.V(1).Info("FibreChannel Try To LockToPod")
			err = LockToPod(b.remoteVolumeServerAddress, b.volName, b.podID)
			if err != nil {
				glog.V(1).Info("FibreChannel LockToPod Failed")
				return false, err
			}
			return true, nil
		}
	} else {
		if podID == "" {
			glog.V(1).Info("FibreChannel Try To RemoteDetach From Node: " + nodeID)
			err := DetachFromServer(b.remoteVolumeServerAddress, nodeID, b.volName)
			if err != nil {
				return false, fmt.Errorf("FibreChannel Volume belong to Node: %v, but not belong to Any Pod,We try release it then MapTo %v,Meet Error: %v", nodeID, b.instanceID, err)
			}
			glog.V(1).Info("FibreChannel Try To RemoteAttach")
			lun, targetWWns, err := FCAttachToServer(b.remoteVolumeServerAddress,b.instanceID, b.volName)
			if err != nil {
				glog.V(1).Info("FibreChannel RemoteAttach Failed %v", err)
				return false, err
			}

			b.fcDisk.lun = strconv.Itoa(lun)
			b.fcDisk.wwns = targetWWns
			glog.V(1).Info("FibreChannel Try To LockToPod")
			err = LockToPod(b.remoteVolumeServerAddress, b.volName, b.podID)
			if err != nil {
				glog.V(1).Info("FibreChannel LockToPod Failed")
				return false, err
			}
			return true, nil
		} else if podID == b.podID {
			if strings.HasPrefix(provide_misc, "fc" ) {
				sep := strings.Split(provide_misc,"|")
				if len(sep) != 3 {
					return false, fmt.Errorf("FibreChannel RemoteAttach Failed: Invalid Provider_Misc : %s", provide_misc)
				} else {
					wwns := strings.Split(sep[1], ",")
					b.fcDisk.lun = sep[2]
					b.fcDisk.wwns = wwns
					return true, nil
				}
			} else {
				return false, fmt.Errorf("FibreChannel RemoteAttach Failed: Invalid Provider_Misc, Can't get wwns,lun")
			}
		} else {
			return false, fmt.Errorf("This Volume is held by another Pod on this Node")
		}
	}
	return true, nil
}

func Lock(b *fcDiskMounter) (bool, error) {
	return LockFibreChannel(b)
}
