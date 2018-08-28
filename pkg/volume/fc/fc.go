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
	"bufio"
	"fmt"
	"github.com/golang/glog"
	"io"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/pkg/api/v1"
	"k8s.io/kubernetes/pkg/util/exec"
	"k8s.io/kubernetes/pkg/util/mount"
	"k8s.io/kubernetes/pkg/util/strings"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/util"
	"os"
	osexec "os/exec"
	"path/filepath"
	fmtstrings "strings"
	"sync"
	"time"
)

// This is the primary entrypoint for volume plugins.
func ProbeVolumePlugins() []volume.VolumePlugin {
	return []volume.VolumePlugin{&fcPlugin{nil, exec.New()}}
}

type fcPlugin struct {
	host volume.VolumeHost
	exe  exec.Interface
}

var _ volume.VolumePlugin = &fcPlugin{}
var _ volume.PersistentVolumePlugin = &fcPlugin{}

const (
	fcPluginName = "kubernetes.io/fc"
)

func (plugin *fcPlugin) Init(host volume.VolumeHost) error {
	plugin.host = host
	return nil
}

func (plugin *fcPlugin) GetPluginName() string {
	return fcPluginName
}

func (plugin *fcPlugin) GetVolumeName(spec *volume.Spec) (string, error) {
	volumeSource, _, err := getVolumeSource(spec)
	if err != nil {
		return "", err
	}

	//  TargetWWNs are the FibreChannel target worldwide names
	return fmt.Sprintf("%v", volumeSource.RemoteVolumeID), nil
}

func (plugin *fcPlugin) CanSupport(spec *volume.Spec) bool {
	if (spec.Volume != nil && spec.Volume.FC == nil) || (spec.PersistentVolume != nil && spec.PersistentVolume.Spec.FC == nil) {
		return false
	}

	return true
}

func (plugin *fcPlugin) RequiresRemount() bool {
	return false
}

func (plugin *fcPlugin) SupportsMountOption() bool {
	return false
}

func (plugin *fcPlugin) SupportsBulkVolumeVerification() bool {
	return false
}

func (plugin *fcPlugin) GetAccessModes() []v1.PersistentVolumeAccessMode {
	return []v1.PersistentVolumeAccessMode{
		v1.ReadWriteOnce,
		v1.ReadOnlyMany,
	}
}

func (plugin *fcPlugin) NewMounter(spec *volume.Spec, pod *v1.Pod, _ volume.VolumeOptions) (volume.Mounter, error) {
	// Inject real implementations here, test through the internal function.
	return plugin.newMounterInternal(spec, pod.UID, &FCUtil{}, plugin.host.GetMounter())
}

func (plugin *fcPlugin) newMounterInternal(spec *volume.Spec, podUID types.UID, manager diskManager, mounter mount.Interface) (volume.Mounter, error) {
	// fc volumes used directly in a pod have a ReadOnly flag set by the pod author.
	// fc volumes used as a PersistentVolume gets the ReadOnly flag indirectly through the persistent-claim volume used to mount the PV
	fc, readOnly, err := getVolumeSource(spec)
	if err != nil {
		return nil, err
	}

	remoteVolumeID := ""
	if spec.PersistentVolume != nil && spec.PersistentVolume.Spec.FC != nil {
		remoteVolumeID = spec.PersistentVolume.Spec.FC.RemoteVolumeID
		glog.V(7).Infof("Try Get RemoteVolumeID from spec.PersistentVolume.Spec.FC: RemoteVolumeID=%v", remoteVolumeID)
	}

	if remoteVolumeID == "" {
		if spec.Volume != nil && spec.Volume.FC != nil {
			remoteVolumeID = spec.Volume.FC.RemoteVolumeID
		}
		glog.V(1).Infof("Try Get RemoteVolumeID from Spec.Volme: RemoteVolumeID=%v", remoteVolumeID)
	}

	//if remoteVolumeID == "" {
	//	return nil, fmt.Errorf("Volume Spec has nil FC.RemoteVolumeID")
	//}

	return &fcDiskMounter{
		fcDisk: &fcDisk{
			podUID:   podUID,
			volName:  spec.Name(),
			volumeID: remoteVolumeID,
			manager:  manager,
			io:       &osIOHandler{},
			plugin:   plugin,
			fcmutex:  plugin.host.GetFcMutex()},
		fsType:                    fc.FSType,
		readOnly:                  readOnly,
		mounter:                   &mount.SafeFormatAndMount{Interface: mounter, Runner: exec.New()},
		remoteVolumeServerAddress: plugin.host.GetRemoteVolumeServerAddress(),
		instanceID:                plugin.host.GetInstanceID(),
		podID:                     string(podUID),
		volumeType:                plugin.host.GetVolumeType(),
	}, nil
}

func (plugin *fcPlugin) NewUnmounter(volName string, podUID types.UID) (volume.Unmounter, error) {
	// Inject real implementations here, test through the internal function.
	return plugin.newUnmounterInternal(volName, podUID, &FCUtil{}, plugin.host.GetMounter())
}

func (plugin *fcPlugin) newUnmounterInternal(volName string, podUID types.UID, manager diskManager, mounter mount.Interface) (volume.Unmounter, error) {
	return &fcDiskUnmounter{
		fcDisk: &fcDisk{
			podUID:  podUID,
			volName: volName,
			manager: manager,
			plugin:  plugin,
			io:      &osIOHandler{},
			fcmutex: plugin.host.GetFcMutex(),
		},
		mounter:                   mounter,
		remoteVolumeServerAddress: plugin.host.GetRemoteVolumeServerAddress(),
		instanceID:                plugin.host.GetInstanceID(),
		podID:                     string(podUID),
		volumeType:                plugin.host.GetVolumeType(),
	}, nil
}

func (plugin *fcPlugin) execCommand(command string, args []string) ([]byte, error) {
	cmd := plugin.exe.Command(command, args...)
	return cmd.CombinedOutput()
}

func (plugin *fcPlugin) ConstructVolumeSpec(volumeName, mountPath string) (*volume.Spec, error) {
	fcVolume := &v1.Volume{
		Name: volumeName,
		VolumeSource: v1.VolumeSource{
			FC: &v1.FCVolumeSource{},
		},
	}
	return volume.NewSpecFromVolume(fcVolume), nil
}

type fcDisk struct {
	volName  string
	podUID   types.UID
	volumeID string
	portal   string
	wwns     []string
	lun      string
	plugin   *fcPlugin
	// Utility interface that provides API calls to the provider to attach/detach disks.
	manager diskManager
	fcmutex *sync.Mutex
	// io handler interface
	io ioHandler
	volume.MetricsNil
}

func (fc *fcDisk) GetPath() string {
	name := fcPluginName
	// safe to use PodVolumeDir now: volume teardown occurs before pod is cleaned up
	return fc.plugin.host.GetPodVolumeDir(fc.podUID, strings.EscapeQualifiedNameForDisk(name), fc.volName)
}

func (fc *fcDisk) GetVolumeIDFilePath() string {
	return fc.plugin.host.GetPodDir(string(fc.podUID))
}

func (fc *fcDisk) RemoveVolumeInfoFile(path string) {
	os.Remove(filepath.Join(path, "volumes", "kubernetes.io~fc", "dellvolumeinfo"))
}

func (fc *fcDisk) WriteVolumeInfoInPluginDir(rootpath string) error {
	//rootpath := fc.GetVolumeIDFilePath()
	volumepath := filepath.Join(rootpath, "volumes", "kubernetes.io~fc", "dellvolumeinfo")
	glog.V(1).Infof("Write VolumeID: %v To %v", fc.volName, volumepath)

	os.Remove(volumepath)
	os.Create(volumepath)

	f, err := os.OpenFile(volumepath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		glog.Errorf("Create_Dellvolumeinfo error: %v", err)
		return err
	}
	defer f.Close()

	_, err = f.WriteString("volName=" + fc.volumeID + "\n")
	if err != nil {
		glog.Errorf("Create_DellvolumeinfoFail to Write VolumeID: %v To %v , Meet %v", fc.volumeID, volumepath, err)
		return fmt.Errorf("Create_Dellvolumeinfo Fail to Write VolumeID: %v To %v , Meet %v", fc.volumeID, volumepath, err)
	}

	_, err = f.WriteString("wwns=" + fmtstrings.Join(fc.wwns, ",") + "\n")
	if err != nil {
		glog.Errorf("Create_Dellvolumeinfo Fail to Write Wwns: %v To %v , Meet %v", fc.wwns, volumepath, err)
		return fmt.Errorf("Fail to Write Wwns: %v To %v , Meet %v", fc.wwns, volumepath, err)
	}

	_, err = f.WriteString("lun=" + fc.lun + "\n")
	if err != nil {
		glog.Errorf("Create_Dellvolumeinfo Fail to Write Lun: %v To %v , Meet %v", fc.lun, volumepath, err)
		return fmt.Errorf("Fail to Write Lun: %v To %v , Meet %v", fc.lun, volumepath, err)
	}
	return nil
}

func (fc *fcDisk) ReadWwnsAndLunFromPluginsDir(path string) (wwns, lun string, err error) {
	volumepath := filepath.Join(path, "volumes", "kubernetes.io~fc", "dellvolumeinfo")
	f, err := os.Open(volumepath)
	if err != nil {
		return wwns, lun, err
	}
	defer f.Close()

	reader := bufio.NewReader(f)

	for {
		line, err := reader.ReadString('\n')
		glog.Infof("dellfc line: %v", line)
		if line != "" {
			line = fmtstrings.TrimRight(line, "\n")
		}
		if err != nil {
			if err != io.EOF {
				sep := fmtstrings.Split(line, "=")
				line = fmtstrings.TrimSuffix(line, "\n")
				if len(sep) == 2 {
					if sep[0] == "wwns" && wwns == "" {
						wwns = sep[1]
					}
					if sep[0] == "lun" && lun == "" {
						lun = sep[1]
					}
				}
				break
			}
		}
		sep := fmtstrings.Split(line, "=")
		if len(sep) == 2 {
			if sep[0] == "wwns" && wwns == "" {
				wwns = sep[1]
			}
			if sep[0] == "lun" && lun == "" {
				lun = sep[1]
			}
		}
		if wwns != "" && lun != "" {
			break
		}
	}

	if lun == "" || wwns == "" {
		err = fmt.Errorf(path + " has bad format, can't parse wwns or lun")
		return wwns, lun, err
	} else {
		return wwns, lun, nil
	}
}

func (fc *fcDisk) ReadVolumeIDFromPluginsDir(path string) (string, error) {
	volumepath := filepath.Join(path, "volumes", "kubernetes.io~fc", "dellvolumeinfo")
	f, err := os.Open(volumepath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	reader := bufio.NewReader(f)

	for {
		volumeID, err := reader.ReadString('\n')
		if volumeID != "" {
			volumeID = fmtstrings.TrimRight(volumeID, "\n")
		}
		if err != nil {
			if err != io.EOF {
				sep := fmtstrings.Split(volumeID, "=")
				volumeID = fmtstrings.TrimSuffix(volumeID, "\n")
				if len(sep) == 2 {
					if sep[0] == "volName" {
						return sep[1], nil
					}
				}

			}
		}
		sep := fmtstrings.Split(volumeID, "=")
		if len(sep) == 2 {
			if sep[0] == "volName" {
				return sep[1], nil
			}
		}

	}

	return "", fmt.Errorf("Not Found")
}

type fcDiskMounter struct {
	*fcDisk
	readOnly                  bool
	fsType                    string
	remoteVolumeServerAddress string
	instanceID                string
	volumeType                string
	podID                     string
	mounter                   *mount.SafeFormatAndMount
}

var _ volume.Mounter = &fcDiskMounter{}

func (b *fcDiskMounter) GetAttributes() volume.Attributes {
	return volume.Attributes{
		ReadOnly:        b.readOnly,
		Managed:         !b.readOnly,
		SupportsSELinux: true,
	}
}

// Checks prior to mount operations to verify that the required components (binaries, etc.)
// to mount the volume are available on the underlying node.
// If not, it returns an error
func (b *fcDiskMounter) CanMount() error {
	return nil
}

func (b *fcDiskMounter) SetUp(fsGroup *int64) error {
	return b.SetUpAt(b.GetPath(), fsGroup)
}

func (b *fcDiskMounter) SetUpAt(dir string, fsGroup *int64) error {
	// diskSetUp checks mountpoints and prevent repeated calls
	b.fcmutex.Lock()
	defer b.fcmutex.Unlock()

	if b.volumeID == "" {
		return fmt.Errorf("Empty FC.RemoteVolumeID")
	}

	_, err := Lock(b)
	if err != nil {
		glog.Errorf(err.Error())
		return err
	}

	err = diskSetUp(b.manager, *b, dir, b.mounter, fsGroup)
	if err != nil {
		// no fc disk found or Is Likely Not MountPoint : we will simply unlock and detach dellvolume
		glog.Errorf("fc: failed to setup: %v", err)
		glog.Errorf("diskSetUp_failed, so we must unlock volume:%v", b.volumeID)
		if err.Error() != "no fc disk found" || err.Error() != "Is Likely Not Mount Point" {
			glog.Errorf("diskSetUp_failed, clean %v", b.volumeID)
			if b.lun != "" && len(b.wwns) != 0 && b.volumeID != "" {
				volumeID := b.volumeID
				wwns := fmtstrings.Join(b.wwns, ",")
				lun := b.lun
				glog.V(1).Infoln("RemoteDellVolume_Clean after disksetup failed")
				out, err2 := osexec.Command("/bin/bash", "-c", "/usr/bin/clean_removal.sh "+wwns+" "+lun+" "+volumeID).CombinedOutput()
				if err2 != nil {
					glog.V(1).Infof("RemoteDellVolume_Clean clean fc device failed, meet error: %v , info: %v,"+
						"volumeID=%v, wwns=%v, lun=%v", err, string(out), volumeID, fmtstrings.Join(b.wwns, ","), lun)
					glog.Errorf("RemoteDellVolume_Clean clean fc device failed, meet error: %v , info: %v", err, string(out))
					//err = fmt.Errorf("clean fc device failed, meet error: %v , info: %v", err, string(out))
					//return err
				}
				err1 := b.UnlockWhenSetupFailed()
				if err1 != nil {
					glog.Errorf("After failure of diskSetUp(%v), So we unlock this volume, but failed: %v", b.volumeID, err1)
					err = fmt.Errorf(err.Error() + "   " + err1.Error())
					glog.Errorf("fc: failed to setup: %v", err)
					return err
				}
				glog.V(1).Infoln("RemoteDellVolume_Clean after disksetup failed")
				osexec.Command("/bin/bash", "-c", "/usr/bin/clean_removal.sh "+wwns+" "+lun+" "+volumeID).CombinedOutput()
			}
		}
	} else {
		b.WriteVolumeInfoInPluginDir(b.GetVolumeIDFilePath())
	}
	return err
}

func (b *fcDiskMounter) UnlockWhenSetupFailed() error {
	glog.V(1).Info("UnlockWhenSetupFailed FibreChannel Unlock Begin")
	glog.V(1).Info("UnlockWhenSetupFailed FibreChannel Unlock, Try to UnlockFromPod Begin")
	err1 := UnlockFromPod(b.remoteVolumeServerAddress, b.volumeID, b.podID)

	glog.V(1).Info("UnlockWhenSetupFailed FibreChannel Unlock, Try to RemoteDetach from Server")
	err2 := DetachFromServer(b.remoteVolumeServerAddress, b.instanceID, b.volumeID)
	if err2 != nil {
		glog.Errorf("UnlockWhenSetupFailed FibreChannel Unlock, RemoteDetach Failed: %v", err2)
		var err error
		if err1 != nil {
			err = fmt.Errorf(err1.Error() + " " + err2.Error())
		} else {
			err = err2
		}
		return err
	}
	return nil

}

type fcDiskUnmounter struct {
	*fcDisk
	mounter                   mount.Interface
	remoteVolumeServerAddress string
	instanceID                string
	volumeType                string
	podID                     string
}

var _ volume.Unmounter = &fcDiskUnmounter{}

// Unmounts the bind mount, and detaches the disk only if the disk
// resource was the last reference to that disk on the kubelet.
func (c *fcDiskUnmounter) TearDown() error {
	return c.TearDownAt(c.GetPath())
}

func (c *fcDiskUnmounter) TearDownAt(dir string) error {
	glog.Infoln("begin uninstall dellfc volume: " + dir)
	c.fcmutex.Lock()
	defer c.fcmutex.Unlock()
	if pathExists, pathErr := util.PathExists(dir); pathErr != nil {
		return fmt.Errorf("Error checking if path exists: %v", pathErr)
	} else if !pathExists {
		glog.Warningf("Warning: Unmount skipped because path does not exist: %v", dir)
		return nil
	}
	volumeID, err := c.ReadVolumeIDFromPluginsDir(c.GetVolumeIDFilePath())
	if err != nil {
		glog.Errorf("Unable to read VolumeID from %v , Meet %v", filepath.Join(c.GetVolumeIDFilePath(), "volumes", "kubernetes.io~fc","dellvolumeinfo"), err)
		return fmt.Errorf("Unable to read VolumeID from %v , Meet %v", filepath.Join(c.GetVolumeIDFilePath(),"volumes","kubernetes.io~fc", "dellvolumeinfo"), err)
	}

	wwns, lun, err := c.ReadWwnsAndLunFromPluginsDir(c.GetVolumeIDFilePath())
	if err != nil {
		glog.Errorf("Unable to read wwns and lun from %v , Meet %v", filepath.Join(c.GetVolumeIDFilePath(),"volumes", "kubernetes.io~fc","dellvolumeinfo"), err)
		return fmt.Errorf("Unable to read wwns and lun from %v , Meet %v", filepath.Join(c.GetVolumeIDFilePath(), "volumes","kubernetes.io~fc","dellvolumeinfo"), err)
	}

	if wwns == "" || lun == "" {
		glog.Errorf("Unable to read wwns and lun from %v , Meet %v", filepath.Join(c.GetVolumeIDFilePath(), "volumes","kubernetes.io~fc", "dellvolumeinfo"), err)
		return fmt.Errorf("Unable to read wwns and lun from %v , Meet %v", filepath.Join(c.GetVolumeIDFilePath(), "volumes", "kubernetes.io~fc", "dellvolumeinfo"), err)
	}

	glog.V(1).Infof("Wwns=%v, Lun=%v , volomeID=%v  dir=%v ", wwns, lun, volumeID, dir)

	dmName := getDMDiskName(fmtstrings.Split(wwns, ","), lun, c.io)

	glog.V(1).Infoln("DMName is: ", dmName)
	err = diskTearDown(c.manager, *c, dir, c.mounter)

	if err != nil {
		glog.Errorf("RemoveDellVolume_Fail Wwns=%v, Lun=%v , volomeID=%v error=%v", wwns, lun, volumeID, err)
		return err
	}

	for true {
		// bash /usr/bin/clean_removal.sh wwns lun
		out, err := osexec.Command("/bin/bash", "-c", "/usr/bin/clean_removal.sh "+wwns+" "+lun+" "+volumeID).CombinedOutput()
		if err != nil {
			glog.Errorf("clean_fc device failed, meet error: %v , info: %v", err, string(out))
			glog.Errorf("clean_fc device failed, volumeID=%v, wwns=%v, lun=%v", volumeID, wwns, lun)
			glog.Errorf("clean_fc device failed, meet error: %v , info: %v", err, string(out))
		}
		if getDMSlaves(dmName, c.io) != 0 {
			time.Sleep( 2 * time.Second )
		} else {
			break
		}
	}

	if volumeID != "" {
		err := Unlock(c.remoteVolumeServerAddress, volumeID, c.podID, c.instanceID)
		if err != nil {
			glog.Errorf("unlock/unmap volume failed: %v", err)
			return err
		}
	}
	glog.V(1).Infof("RemoveDellVolume_Success Wwns=%v, Lun=%v , volomeID=%v", wwns, lun, volumeID)
	c.RemoveVolumeInfoFile(c.GetVolumeIDFilePath())
	return err
}

func getVolumeSource(spec *volume.Spec) (*v1.FCVolumeSource, bool, error) {
	if spec.Volume != nil && spec.Volume.FC != nil {
		return spec.Volume.FC, spec.Volume.FC.ReadOnly, nil
	} else if spec.PersistentVolume != nil &&
		spec.PersistentVolume.Spec.FC != nil {
		return spec.PersistentVolume.Spec.FC, spec.ReadOnly, nil
	}

	return nil, false, fmt.Errorf("Spec does not reference a FibreChannel volume type")
}
