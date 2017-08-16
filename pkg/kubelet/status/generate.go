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

package status

import (
	"fmt"
	"strings"

	"k8s.io/kubernetes/pkg/api/v1"
)

const (
	UnknownContainerStatuses = "UnknownContainerStatuses"
	PodCompleted             = "PodCompleted"
	ContainersNotReady       = "ContainersNotReady"
	ContainersNotInitialized = "ContainersNotInitialized"
)

//<author xufei>: compare old containers and new containers
func IsPodContainersDiff(spec *v1.PodSpec, oldContainerStatuses []v1.ContainerStatus, newContainerStatuses []v1.ContainerStatus) bool {
	var different bool = false

	for _, container := range spec.Containers {
		oldContainerStatus, findOldOk := v1.GetContainerStatus(oldContainerStatuses, container.Name)
		newContainerStatus, findNewOk := v1.GetContainerStatus(newContainerStatuses, container.Name)
		if findNewOk && findOldOk {
			if oldContainerStatus.ContainerID != newContainerStatus.ContainerID {
				different = true
				break
			}
			if oldContainerStatus.Ready != newContainerStatus.Ready {
				different = true
				break
			}

		} else {
			different = true
			break
		}
	}
	return different
}

//<author xufei>: judge pod status by it's containers' status
func IsPodReady(spec *v1.PodSpec, containerStatuses []v1.ContainerStatus) bool {
	var ready bool = true

	for _, container := range spec.Containers {
		if containerStatus, ok := v1.GetContainerStatus(containerStatuses, container.Name); ok {
			if !containerStatus.Ready {
				ready = false
				break
			}
		} else {
			ready = false
			break
		}
	}
	return ready
}

// GeneratePodReadyCondition returns ready condition if all containers in a pod are ready, else it
// returns an unready condition.
func GeneratePodReadyCondition(spec *v1.PodSpec, containerStatuses []v1.ContainerStatus, podPhase v1.PodPhase) v1.PodCondition {
	// Find if all containers are ready or not.
	if containerStatuses == nil {
		return v1.PodCondition{
			Type:   v1.PodReady,
			Status: v1.ConditionFalse,
			Reason: UnknownContainerStatuses,
		}
	}
	unknownContainers := []string{}
	unreadyContainers := []string{}
	for _, container := range spec.Containers {
		if containerStatus, ok := v1.GetContainerStatus(containerStatuses, container.Name); ok {
			if !containerStatus.Ready {
				unreadyContainers = append(unreadyContainers, container.Name)
			}
		} else {
			unknownContainers = append(unknownContainers, container.Name)
		}
	}

	// If all containers are known and succeeded, just return PodCompleted.
	if podPhase == v1.PodSucceeded && len(unknownContainers) == 0 {
		return v1.PodCondition{
			Type:   v1.PodReady,
			Status: v1.ConditionFalse,
			Reason: PodCompleted,
		}
	}

	unreadyMessages := []string{}
	if len(unknownContainers) > 0 {
		unreadyMessages = append(unreadyMessages, fmt.Sprintf("containers with unknown status: %s", unknownContainers))
	}
	if len(unreadyContainers) > 0 {
		unreadyMessages = append(unreadyMessages, fmt.Sprintf("containers with unready status: %s", unreadyContainers))
	}
	unreadyMessage := strings.Join(unreadyMessages, ", ")
	if unreadyMessage != "" {
		return v1.PodCondition{
			Type:    v1.PodReady,
			Status:  v1.ConditionFalse,
			Reason:  ContainersNotReady,
			Message: unreadyMessage,
		}
	}

	return v1.PodCondition{
		Type:   v1.PodReady,
		Status: v1.ConditionTrue,
	}
}

// GeneratePodInitializedCondition returns initialized condition if all init containers in a pod are ready, else it
// returns an uninitialized condition.
func GeneratePodInitializedCondition(spec *v1.PodSpec, containerStatuses []v1.ContainerStatus, podPhase v1.PodPhase) v1.PodCondition {
	// Find if all containers are ready or not.
	if containerStatuses == nil && len(spec.InitContainers) > 0 {
		return v1.PodCondition{
			Type:   v1.PodInitialized,
			Status: v1.ConditionFalse,
			Reason: UnknownContainerStatuses,
		}
	}
	unknownContainers := []string{}
	unreadyContainers := []string{}
	for _, container := range spec.InitContainers {
		if containerStatus, ok := v1.GetContainerStatus(containerStatuses, container.Name); ok {
			if !containerStatus.Ready {
				unreadyContainers = append(unreadyContainers, container.Name)
			}
		} else {
			unknownContainers = append(unknownContainers, container.Name)
		}
	}

	// If all init containers are known and succeeded, just return PodCompleted.
	if podPhase == v1.PodSucceeded && len(unknownContainers) == 0 {
		return v1.PodCondition{
			Type:   v1.PodInitialized,
			Status: v1.ConditionTrue,
			Reason: PodCompleted,
		}
	}

	unreadyMessages := []string{}
	if len(unknownContainers) > 0 {
		unreadyMessages = append(unreadyMessages, fmt.Sprintf("containers with unknown status: %s", unknownContainers))
	}
	if len(unreadyContainers) > 0 {
		unreadyMessages = append(unreadyMessages, fmt.Sprintf("containers with incomplete status: %s", unreadyContainers))
	}
	unreadyMessage := strings.Join(unreadyMessages, ", ")
	if unreadyMessage != "" {
		return v1.PodCondition{
			Type:    v1.PodInitialized,
			Status:  v1.ConditionFalse,
			Reason:  ContainersNotInitialized,
			Message: unreadyMessage,
		}
	}

	return v1.PodCondition{
		Type:   v1.PodInitialized,
		Status: v1.ConditionTrue,
	}
}
