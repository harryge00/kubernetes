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

package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"k8s.io/kubernetes/pkg/api"
	cmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"
)

func NewCmdOpenUI(f *cmdutil.Factory, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use: "open-ui",
		Short:   "Start a local proxy and open a browser or look for UI's service, get it's external endpoint and open a browser with it",
		Run: func(cmd *cobra.Command, args []string) {
			err := RunOpenUI(f, out)
			cmdutil.CheckErr(err)
		},
	}
	return cmd
}

func RunOpenUI(f *cmdutil.Factory, w io.Writer) error {

	client, err := f.Client()
	if err != nil {
		return err
	}
	var ops api.ListOptions
	namespaces, err := client.Namespaces().List(ops)
	if err != nil {
		return fmt.Errorf("Couldn't get Namespaces from server: %v\n", err)
	}
	for _, n := range namespaces.Items {
		fmt.Fprintln(w, n.Name)
		fmt.Fprintln(w, n.Status.Phase)
		if n.Status.Phase == api.NamespaceActive {
			services, err := client.Services(n.Name).List(ops)
			if err != nil {
				return fmt.Errorf("Couldn't get Service from server: %v\n", err)
			}
			for _, s := range services.Items {
				fmt.Fprintln(w, s.Name)
				if s.Name == "kubernetes-dashboard" {
					fmt.Fprintln(w, n.Name + "/" + s.Name)
				}
			}
		}
	}
	fmt.Fprintln(w, "not implemented")
	return nil
}
