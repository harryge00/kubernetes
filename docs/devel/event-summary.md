## client
JobPodAdd
JobPodDelete
RcPodAdd
RcPodDelete
## scheduler
FailedScheduling: failed to schedule the special pod
Scheduled: succeed to schedule the pod
## controller
DeadlineExceeded: Job was active longer than specified deadline
DeadlineCountExceeded: Job's pod failed count larger than specified DeadlineCount
TooManyActivePods:Too many active pods running after completion count reached
TooManySucceededPods: Too many succeeded pods running after completion count reached
FailedDeletePodReason: fail to delete pod 
SuccessfulDeletePodReason: successful delete pod 
RcUpdate: rc update pod 
JobUpdate: job update pod

## kubelet
### node级别
1. NodeReady(normal): Node is healthy and ready to accept pod
2. NodeNotReady(normal): Node is unhealthy, unable to accept and setup pod
3. NodeHasInsufficientMemory(normal): node has insufficient memmory
4. NodeHasSufficientMemory(normal): node has sufficient memmory
5. NodeHasDiskPressure(normal) : node has disk pressure, disk space is tiny.
6. NodeHasNoDiskPressure(normal): node has node disk pressure
7. NodeOutOfDisk(normal): node has no disk space
9. NodeNotSchedulable(normal): node can't be taken by scheduler
10. NodeSchedulable(normal): node can be taken by scheduler, kube=scheduler can dispatch pod to this node
11. SuccessfulNodeAllocatableEnforcement: 
12. FailedNodeAllocatableEnforcement
13. FailedNodeAllocatableEnforcement
14. KubeletSetupFailed: kubelet bootstrap failed
15. StartingKubelet: kubelet bootstarp successfully
16. NodeRebooted: detake node reboot operation

### pod级别
1. 环境变量: InvalidEnvironmentVariableNames(warnning) 非法环境变量
2.
### 镜像
```flow
st=>start: Start
getImageTag=>operation: GetImageTag
getImageTagFail=>condition: GetImageTag Fail?
FailedToInspectImage=>operation: FailedToInspectImage Event
shouldPullImage=>condition: should pull image?
imagePresentOnHost=>condition: Image is present on host?
PulledImage=>operation: PulledImage Event
ErrImageNeverPullPolicy=>operation: ErrImageNeverPullPolicy Event
BackOffPullImage=>operation: BackOffPullImage Event
PullingImage=>operation: PullingImage Event
FailedToPullImage=>operation: FailedToPullImage Event
PulledImage=>operation: PulledImage Event
BackOffPullmage=>condition: Pulling Image Failed
PullingImageFailed=>condition: PullingImage Failed?
end=>end

st->getImageTag->getImageTagFail
getImageTagFail(yes)->FailedToInspectImage->end
getImageTagFail(no)->shouldPullImage
shouldPullImage(yes)->imagePresentOnHost
imagePresentOnHost(yes)->PulledImage->end
shouldPullImage(no)->ErrImageNeverPullPolicy->end
imagePresentOnHost(no)->PullingImage->BackOffPullmage
BackOffPullmage(yes)->BackOffPullImage->end
BackOffPullmage(no)->PullingImage->PullingImageFailed
PullingImageFailed(no)->PulledImage->end
PullingImageFailed(yes)->FailedToPullImage->end
```
### 容器启动
```flow
start=>start
getConfig=>condition: getConfig Failed?
FailedToCreateContainer=>operation: FailedToCreateContainer Event
CreatedContainer=>operation: CreatedContainer Event
startContainerFailed=>condition: Start Container Failed?
StartedContainer=>operation: StartedContainer Event
FailedToStartContainer=>operation: FailedToStartContainer Event

end=>end

start->getConfig
getConfig(yes)->CreatedContainer->StartedContainer->startContainerFailed
getConfig(no)->FailedToCreateContainer->end
startContainerFailed(yes)->FailedToStartContainer->end
```
其余：
SandboxChanged Event:检查Infra情况
杀死容器的相关event:
FailedPreStopHook: before kill pod, kubelet will do some pre-kill operation, if this operation failed, alert this event
UnfinishedPreStopHook: if container did not complete preStop operation in some seconds, this event will be sent
KillingContainer: kill container succesfully
OutOfDisk: lack Disk in order to unable to setup pod

##### 容器启动
BackOffStartContainer：Back-off restarting failed docker container

##### 容器健康状态
ContainerUnhealthy： container probe error

#####pod evication:
PreemptContainer:  attempting to evict pods, in order to free up resources
##### 容器同步
FailedSync: error syncing pod.
ExceededGracePeriod: Container runtime did not kill the pod within specified grace period.
##### kubelet转换标准api pod
FailedConversion: Error converting pod 
FailedValidation: Error validating pod
##### GC 
InvalidDiskCapacity: invalid capacity on device xxx at mount point xxx
FreeDiskSpaceFailed: failed to garbage collect required amount of images.
ContainerGCFailed: Container garbage collection failed
ImageGCFailed: Image garbage collection failed
##### network 
MissingClusterDNS: kubelet does not have ClusterDNS IP configured and cannot create Pod using special policy. Warning events.
HostNetworkNotSupported: Bandwidth shaping is not currently supported on the host network.
UndefinedShaper: Pod requests bandwidth shaping, but the shaper is undefined.
DNSSearchForming: Found and omitted duplicated dns domain in host search line.
checkLimitsForResolvConf: check dns resolv config, normal event.
##### volume 
FailedMountVolume: Unable to mount volumes for pod 
FailedUnMountVolume: Ubale to unmount volumes for pod                 
SuccessfulDetachVolume: Successful detach volume               
SuccessfulMountVolume: Successful Mount Volume               
SuccessfulUnMountVolume: Sucessful Unmount Volume
##### scheduler
kubelet在接受到pod的时候，会重新将pod走一遍调度.
HostPortConflict: local host port conflict
NodeSelectorMismatching: Node selector mismatch this node label
InsufficientFreeCPU: lack cpu resource to run this pod
InsufficientFreeMemory: lack memmory resource to run this pod              
OutOfDisk: lack disk resource to run this pod
UnsupportedMountOption: mount option is mismatch 