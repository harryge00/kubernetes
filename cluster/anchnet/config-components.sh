#!/bin/bash

# Copyright 2015 The Kubernetes Authors All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Assumed vars (defined in config-default.sh):
#   MASTER_INSECURE_ADDRESS
#   MASTER_INSECURE_PORT
#   MASTER_SECURE_ADDRESS
#   MASTER_SECURE_PORT

# Create etcd options used to start etcd on master, see following documentation:
#   https://github.com/coreos/etcd/blob/master/Documentation/clustering.md
# Note since we have only one master right now, the options here do not contain
# clustering options, like initial-advertise-peer-urls, listen-peer-urls, etc.
#
# Input:
#   $1 Instance name appearing to etcd. E.g. kubernetes-master, kubernetes-node0, etc.
function create-etcd-opts {
  cat <<EOF > ~/kube/default/etcd
ETCD_OPTS="-name ${1} \
--listen-client-urls http://0.0.0.0:4001 \
--advertise-client-urls http://127.0.0.1:4001"
EOF
}

# Create apiserver options.
#
# Input:
#   $1 Service IP range. All kubernetes service will fall into the range.
#   $2 Admmission control plugins.
#   $3 Unique cluster name.
function create-kube-apiserver-opts {
  cat <<EOF > ~/kube/default/kube-apiserver
KUBE_APISERVER_OPTS="--logtostderr=true \
--insecure-bind-address=${MASTER_INSECURE_ADDRESS} \
--cors-allowed-origins=.*
--insecure-port=${MASTER_INSECURE_PORT} \
--bind-address=${MASTER_SECURE_ADDRESS} \
--secure-port=${MASTER_SECURE_PORT} \
--etcd-servers=http://127.0.0.1:4001 \
--service-cluster-ip-range=${1} \
--token-auth-file=/etc/kubernetes/known-tokens.csv \
--basic-auth-file=/etc/kubernetes/basic-auth.csv \
--client-ca-file=/etc/kubernetes/ca.crt \
--tls-cert-file=/etc/kubernetes/master.crt \
--tls-private-key-file=/etc/kubernetes/master.key \
--admission-control=${2} \
--cloud-config=/etc/kubernetes/anchnet-config \
--cloud-provider=anchnet \
--cluster-name=${3}"
EOF
}

# Create controller manager options.
# Input:
#   $1 Unique cluster name.
function create-kube-controller-manager-opts {
  cat <<EOF > ~/kube/default/kube-controller-manager
KUBE_CONTROLLER_MANAGER_OPTS="--logtostderr=true \
--master=${MASTER_INSECURE_ADDRESS}:${MASTER_INSECURE_PORT} \
--cloud-config=/etc/kubernetes/anchnet-config \
--cloud-provider=anchnet \
--service-account-private-key-file=/etc/kubernetes/master.key \
--root-ca-file=/etc/kubernetes/ca.crt \
--cluster-name=${1}"
EOF
}

# Create scheduler options.
function create-kube-scheduler-opts {
  cat <<EOF > ~/kube/default/kube-scheduler
KUBE_SCHEDULER_OPTS="--logtostderr=true \
--master=${MASTER_INSECURE_ADDRESS}:${MASTER_INSECURE_PORT}"
EOF
}

# Create kubelet options.
#
# Input:
#   $1 Hostname override - override hostname used in kubelet.
#   $2 Address to bind
#   $2 API server address, typically master internal IP address.
#   $3 Cluster DNS IP address, should fall into service ip range.
#   $4 Cluster search domain, e.g. cluster.local
#   $5 Pod infra image, i.e. the pause. Default pause image comes from gcr, which is
#      sometimes blocked by GFW.
function create-kubelet-opts {
  # Lowercase input value.
  local hostname=$(echo $1 | tr '[:upper:]' '[:lower:]')
  cat <<EOF > ~/kube/default/kubelet
KUBELET_OPTS="--logtostderr=true \
--address=${2} \
--port=10250 \
--system-container=/system \
--cgroup-root=/ \
--hostname_override=${hostname} \
--api-servers=https://${3}:${MASTER_SECURE_PORT} \
--cluster-dns=${4} \
--cluster-domain=${5} \
--pod-infra-container-image=${6} \
--config=/etc/kubernetes/manifest \
--kubeconfig=/etc/kubernetes/kubelet-kubeconfig \
--cloud-config=/etc/kubernetes/anchnet-config \
--cloud-provider=anchnet"
EOF
}

# Create kube-proxy options.
#
# Input:
#   $1 API server address, typically master internal IP address
function create-kube-proxy-opts {
  cat <<EOF > ~/kube/default/kube-proxy
KUBE_PROXY_OPTS="--logtostderr=true \
--master=https://${1}:${MASTER_SECURE_PORT} \
--kubeconfig=/etc/kubernetes/kube-proxy-kubeconfig"
EOF
}

# Create flanneld options.
#
# Input:
#   $1 Interface used by flanneld to send internal traffic. Because we use anchnet
#      private SDN network, this should be set to the instance's SDN private IP.
#   $2 etcd service endpoint IP address. For master, this is 127.0.0.1; for node,
#      this is master internal IP address.
function create-flanneld-opts {
  cat <<EOF > ~/kube/default/flanneld
FLANNEL_OPTS="--iface=${1} --etcd-endpoints=http://${2}:4001"
EOF
}

# Config flanneld options in etcd. The method is called from master.
#
# Input:
#   $1 Flannel overlay network CIDR
function config-etcd-flanneld {
  attempt=0
  while true; do
    echo "Attempt $(($attempt+1)) to set flannel configuration in etcd"
    /opt/bin/etcdctl get "/coreos.com/network/config"
    if [[ "$?" == 0 ]]; then
      break
    else
      # Give a large timeout since this depends on status of etcd on
      # other machines.
      if (( attempt > 600 )); then
        echo "timeout waiting for network config"
        exit 2
      fi
      /opt/bin/etcdctl mk "/coreos.com/network/config" "{\"Network\":\"$1\"}"
      attempt=$((attempt+1))
      sleep 3
    fi
  done
}

# Configure docker network settings to use flannel overlay network.
#
# Input:
#   $1 Registry mirror address
function restart-docker {
  # Wait for /run/flannel/subnet.env to be ready.
  attempt=0
  while true; do
    echo "Attempt $(($attempt+1)) to check for subnet.env set by flannel"
    if [[ -f /run/flannel/subnet.env ]] && \
         grep -q "FLANNEL_SUBNET" /run/flannel/subnet.env && \
         grep -q "FLANNEL_MTU" /run/flannel/subnet.env ; then
      break
    else
      if (( attempt > 60 )); then
        echo "timeout waiting for subnet.env from flannel"
        exit 2
      fi
      attempt=$((attempt+1))
      sleep 3
    fi
  done

  # In order for docker to correctly use flannel setting, we first stop docker,
  # flush nat table, delete docker0 and then start docker. Missing any one of
  # the steps may result in wrong iptable rules, see:
  # https://github.com/caicloud/caicloud-kubernetes/issues/25
  sudo service docker stop
  sudo iptables -t nat -F
  sudo ip link set dev docker0 down
  sudo brctl delbr docker0

  source /run/flannel/subnet.env
  echo DOCKER_OPTS=\"-H tcp://127.0.0.1:4243 -H unix:///var/run/docker.sock \
       --bip=${FLANNEL_SUBNET} --mtu=${FLANNEL_MTU} --registry-mirror=$1 \
       --insecure-registry=internal-registry.caicloud.io\" > /etc/default/docker
  sudo service docker start
}

# Set hostname of an instance. In anchnet, hostname has the same format but
# different value than instance ID. We don't need the random hostname given
# by anchnet.
#
# Input:
#   $1 instance ID
function config-hostname {
  # Lowercase input value.
  local new_hostname=$(echo $1 | tr '[:upper:]' '[:lower:]')

  # Return early if hostname is already new.
  if [[ "`hostname`" == "${new_hostname}" ]]; then
    return
  fi

  if which hostnamectl > /dev/null; then
    hostnamectl set-hostname "${new_hostname}"
  else
    echo "${new_hostname}" > /etc/hostname
    hostname "${new_hostname}"
  fi

  if grep '127\.0\.1\.1' /etc/hosts > /dev/null; then
    sed -i "s/127\.0\.1\.1.*/127.0.1.1 ${new_hostname}/g" /etc/hosts
  else
    echo -e "127.0.1.1\t${new_hostname}" >> /etc/hosts
  fi

  echo "Hostname settings have been changed to ${new_hostname}."
}

# Add an entry in /etc/hosts file if not already exists. This is used for master to
# contact kubelet using hostname, as anchnet is unable to do hostname resolution.
#
# Input:
#   $1 hostname
#   $2 host IP address
function add-hosts-entry {
  # Lowercase input value.
  local new_hostname=$(echo $1 | tr '[:upper:]' '[:lower:]')

  if ! grep "$new_hostname" /etc/hosts > /dev/null; then
    echo -e "$2 $new_hostname" >> /etc/hosts
  fi
}
