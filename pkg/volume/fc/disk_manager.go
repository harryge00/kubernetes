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

package fc

import (
	"os"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/util/mount"
	"k8s.io/kubernetes/pkg/volume"
	"fmt"
	"path/filepath"
	"strings"
)

// Abstract interface to disk operations.
type diskManager interface {
	MakeGlobalPDName(disk fcDisk) string
	// Attaches the disk to the kubelet's host machine.
	AttachDisk(b fcDiskMounter) error
	// Detaches the disk from the kubelet's host machine.
	DetachDisk(disk fcDiskUnmounter, mntPath string) error
}

// utility to mount a disk based filesystem
func diskSetUp(manager diskManager, b fcDiskMounter, volPath string, mounter mount.Interface, fsGroup *int64) error {
	globalPDPath := manager.MakeGlobalPDName(*b.fcDisk)
	// TODO: handle failed mounts here.
	noMnt, err := mounter.IsLikelyNotMountPoint(volPath)

	if err != nil && !os.IsNotExist(err) {
		glog.Errorf("step_1: cannot validate mountpoint: %s", volPath)
		return fmt.Errorf("Is Likely Not Mount Point")
	}
	if !noMnt {
		return nil
	}
	if err := manager.AttachDisk(b); err != nil {
		glog.Errorf("step_2: failed to attach disk")
		return err
	}

	if err := os.MkdirAll(volPath, 0750); err != nil {
		glog.Errorf("step_3: failed to mkdir:%s", volPath)
		return err
	}
	// Perform a bind mount to the full path to allow duplicate mounts of the same disk.
	options := []string{"bind"}
	if b.readOnly {
		options = append(options, "ro")
	}
	err = mounter.Mount(globalPDPath, volPath, "", options)
	if err != nil {
		mounter.Unmount(volPath)
		glog.Errorf("step_4: failed to bind mount:%s", globalPDPath)
		return err
	}

	if !b.readOnly {
		volume.SetVolumeOwnership(&b, fsGroup)
	}

	return nil
}


func getDMDiskName(wwns []string, lun string, io ioHandler) string {
	for _, wwn := range wwns {
		_, dm := findDisk(wwn, lun, io)
		if dm != "" {
			return dm
		}
	}
	return ""
}

func getDMSlaves(dm string, io ioHandler) int {
	dmNames := strings.Split(dm,"/")
	if len(dmNames) != 3 {
		return 0
	}
	slaves, err := io.ReadDir("/sys/block/" + dmNames[2] + "/slaves/")
	if err != nil {
		glog.V(1).Infof("RemoveDellVolume_Fail GetDMSlaves error: ", err.Error())
		return 0
	} else {
		glog.V(1).Infof("RemoveDellVolume_Fail GetDMSlaves Numbers: ", string(len(slaves)))
		return len(slaves)
	}
}

// utility to tear down a disk based filesystem
func diskTearDown(manager diskManager, c fcDiskUnmounter, volPath string, mounter mount.Interface) error {
	noMnt, err := mounter.IsLikelyNotMountPoint(volPath)
	if err != nil {
		glog.V(1).Infof("RemoveDellVolume_Fail Step 1")
		glog.V(1).Infof("cannot validate mountpoint %s, error is %v", volPath, err)
		glog.Errorf("cannot validate mountpoint %s, error is %v", volPath, err)
		return err
	}
	if noMnt {
		glog.V(1).Infof("RemoveDellVolume_Fail Step 2: " + filepath.Join(volPath, "fcvolume"))
		return os.Remove(filepath.Join(volPath))
	}

	refs, err := mount.GetMountRefs(mounter, volPath)
	if err != nil {
		glog.V(1).Infof("RemoveDellVolume_Fail Step 3")
		glog.V(1).Infof("failed to get reference count %s, error is %v", volPath, err)
		glog.Errorf("failed to get reference count %s, error is %v", volPath, err)
		return err
	}
	if err := mounter.Unmount(volPath); err != nil {
		glog.V(1).Infof("RemoveDellVolume_Fail Step 4")
		glog.V(1).Infof("failed to unmount %s , error is %v", volPath, err)
		glog.Errorf("failed to unmount %s , error is %v", volPath, err)
		return err
	}
	// If len(refs) is 1, then all bind mounts have been removed, and the
	// remaining reference is the global mount. It is safe to detach.
	if len(refs) == 1 {
		mntPath := refs[0]
		if err := manager.DetachDisk(c, mntPath); err != nil {
			glog.V(1).Infof("RemoveDellVolume_Fail Step 5")
			glog.V(1).Infof("failed to detach disk from %s , error is %v", mntPath, err)
			glog.Errorf("failed to detach disk from %s , error is %v", mntPath, err)
			return err
		}
	}

	noMnt, mntErr := mounter.IsLikelyNotMountPoint(volPath)
	if mntErr != nil {
		glog.V(1).Infof("RemoveDellVolume_Fail Step 6")
		glog.V(1).Infof("isMountpoint check failed: %v", mntErr)
		glog.Errorf("isMountpoint check failed: %v", mntErr)
		return err
	}
	if noMnt {
		if err := os.Remove(filepath.Join(volPath)); err != nil {
			glog.V(1).Infof("RemoveDellVolume_Fail Step 7")
			glog.V(1).Infof("Remote MountPath %v Failedcheck failed: %v", volPath , err)
			glog.Errorf("Remote MountPath %v Failedcheck failed: %v", volPath , err)
			return err
		}
	}
	return nil

}
