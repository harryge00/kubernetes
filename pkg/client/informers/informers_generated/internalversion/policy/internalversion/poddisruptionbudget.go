/*
Copyright 2018 The Kubernetes Authors.

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

// This file was automatically generated by informer-gen

package internalversion

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
	policy "k8s.io/kubernetes/pkg/apis/policy"
	internalclientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	internalinterfaces "k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion/internalinterfaces"
	internalversion "k8s.io/kubernetes/pkg/client/listers/policy/internalversion"
	time "time"
)

// PodDisruptionBudgetInformer provides access to a shared informer and lister for
// PodDisruptionBudgets.
type PodDisruptionBudgetInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() internalversion.PodDisruptionBudgetLister
}

type podDisruptionBudgetInformer struct {
	factory internalinterfaces.SharedInformerFactory
}

func newPodDisruptionBudgetInformer(client internalclientset.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	sharedIndexInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				return client.Policy().PodDisruptionBudgets(v1.NamespaceAll).List(options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				return client.Policy().PodDisruptionBudgets(v1.NamespaceAll).Watch(options)
			},
		},
		&policy.PodDisruptionBudget{},
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	return sharedIndexInformer
}

func (f *podDisruptionBudgetInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&policy.PodDisruptionBudget{}, newPodDisruptionBudgetInformer)
}

func (f *podDisruptionBudgetInformer) Lister() internalversion.PodDisruptionBudgetLister {
	return internalversion.NewPodDisruptionBudgetLister(f.Informer().GetIndexer())
}
