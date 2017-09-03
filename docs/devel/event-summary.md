## client
JobPodAdd
JobPodDelete
RcPodAdd
RcPodDelete
## scheduler
FailedScheduling
Scheduled
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
1. NodeReady(normal) 
2. NodeNotReady(normal)
3. NodeHasInsufficientMemory(normal)
4. NodeHasSufficientMemory(normal)
5. NodeHasDiskPressure(normal) 
6. NodeHasNoDiskPressure(normal)
7. NodeOutOfDisk(normal) 
8. NodeHasSufficientDisk(normal)
9. NodeNotSchedulable(normal) 
10. NodeSchedulable(normal) 
11. SuccessfulNodeAllocatableEnforcement 
12. FailedNodeAllocatableEnforcement
13. FailedNodeAllocatableEnforcement
14. KubeletSetupFailed
15. StartingKubelet
16. NodeRebooted

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
FailedPreStopHook: preStop hook event
UnfinishedPreStopHook: if container did not complete in some seconds, this event will send
KillingContainer: finnish to kill container
OutOfDisk: OutOfDisk can't setup pod

##### 容器启动
BackOffStartContainer：Back-off restarting failed docker container
##### 容器健康状态
ContainerUnhealthy： container probe error
pod evication:
PreemptContainer:  attempting to evict pods, in order to free up resources
##### 容器同步
FailedSync: error syncing pod
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
MissingClusterDNS: dns 
HostNetworkNotSupported: Bandwidth shaping is not currently supported on the host network
UndefinedShaper: Pod requests bandwidth shaping, but the shaper is undefined
DNSSearchForming: Found and omitted duplicated dns domain in host search line
checkLimitsForResolvConf: 
##### volume 
FailedMountVolume: Unable to mount volumes for pod 
FailedUnMountVolume                 
SuccessfulDetachVolume               
SuccessfulMountVolume               
SuccessfulUnMountVolume 
##### scheduler
HostPortConflict                     
NodeSelectorMismatching              
InsufficientFreeCPU                  
InsufficientFreeMemory              
OutOfDisk       
UnsupportedMountOption