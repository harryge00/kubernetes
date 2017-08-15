# 更新 API 字段的步骤
`Note：本文档基于 Kubernetes v1.6.7 (对应 GitLab 上 kubernetes 的 1.6-release 分支)`
## 代码修改
修改 pkg/api/types.go 和 pkg/api/v1/types.go 相应的代码，增加相应的字段；

## 执行 hack/update-all.sh 更新字段
### 前提条件
执行 hack/update-all.sh 过程中需要两个镜像：  
```
gcr.io/google_containers/kube-cross:v1.7.6-k8s1.6-0   
gcr.io/google_containers/gen-swagger-docs:v8  
```  
如果能翻墙，直接 docker pull 获取即可。如果不能，执行如下操作从私有镜像仓库获取：  
#### kube-cross 镜像
获取私有镜像：  
```
docker pull reg.dhdc.com/luobingli/kube-cross:v1.7.6-k8s1.6-0
```  
然后改tag为：  
```
docker tag reg.dhdc.com/luobingli/kube-cross:v1.7.6-k8s1.6-0  gcr.io/google_containers/kube-cross:v1.7.6-k8s1.6-0
```

#### gen-swagger-docs 镜像
获取私有镜像：  
```
docker pull reg.dhdc.com/wangzhuzhen/gen-swagger-docs:v8
```  
然后改tag为：  
```
docker tag reg.dhdc.com/wangzhuzhen/gen-swagger-docs:v8 gcr.io/google_containers/gen-swagger-docs:v8
```

### 修改文件执行权限  
执行更新字段的脚本前，可能需要修改执行脚本的权限，自己 git clone 的代码可能其中的脚本都没有可执行权限.执行下面的命令进行修改（如有未修改到的脚本权限，直接手动修改添加执行权限即可）：  
```
cd  ${KUBE_ROOT}    // eg: /opt/go/src/k8s.io/kubernetes
chmod -R +x hack/
chmod +x build/*.sh
chmod +x vendor/k8s.io/kube-aggregator/hack/update-codegen.sh
```

### 修改执行脚本
修改 vendor/k8s.io/kube-aggregator/hack/update-codegen.sh 文件，将  
```
KUBE_ROOT=$(dirname "${BASH_SOURCE}")/../../../../..
```
修改为：
```
KUBE_ROOT=$(dirname "${BASH_SOURCE}")/../../../..
```

修改脚本 hack/godep-restore.sh，注释掉下面这行:
```
#GOPATH=${GOPATH}:${KUBE_ROOT}/staging godep restore "$@"
```
### 构建依赖文件
将 k8s.io/kubernetes/vendor下的文件copy一份到与k8s.io目录同级下(也就是$GOPATH/src/k8s.io目录的上级目录 $GOPATH/src/ 中)  
```
cp -r vendor/* $GOPATH/src/
```
### 设置环境变量(如果配置唯一，可忽略此步骤)
设置GOPATH和KUBE_ROOT环境变量  
```
export GOPATH=/opt/go
export KUBE_ROOT=/opt/go/src/k8s.io/kubernetes
```
### 执行脚本更新 API 字段
执行
```
bash hack/update-all.sh -v -a  
```
如有错误，根据日志提示解决

## 编译kubernetes
执行如下命令
```
cd ${KUBE_ROOT}
make
```
编译成功后，在  `${KUBE_ROOT}/_output/bin` 下生成 kubernetes 各种可执行文件，如 `kube-apiserver`, `kubelet`,`kube-controller-manager` 等等，将其替换到 kubernetes 集群即可。




## 遇到的问题
### 1.  k8s 1.5.x 的版本中升级 apiserver 为1.6.x 版本之后，kubectl get 命令挂起
#### 1.1 问题现象
更新 Kubernetes 集群（etcd 使用 2.x.x 版本）的 kube-apiserver 之后， kubectl get 命令会挂起，可以从如下两个方式确定挂起：
(1) 从 kube-apiserver 的 status 查看
```
systemctl  status   kube-apiserver  -l

● kube-apiserver.service - Kube apiserver Daemon
   Loaded: loaded (/usr/lib/systemd/system/kube-apiserver.service; enabled)
   Active: active (running) since 四 2017-07-13 16:39:11 CST; 9min ago
 Main PID: 13283 (kube-apiserver)
   CGroup: /system.slice/kube-apiserver.service
           └─13283 /usr/bin/kube-apiserver --logtostderr=false --v=6 --log-dir=/mnt/log/kubernetes --insecure-bind-address=0.0.0.0 --insecure-port=8080 --admission_control=NamespaceLifecycle,NamespaceExists,LimitRanger,SecurityContextDeny,ResourceQuota --kubelet_port=10250 --etcd_servers=http://10.35.48.172:2379 --master-service-namespace=master --secure-port=6443 --bind-address=0.0.0.0 --allow_privileged=false --service-cluster-ip-range=10.0.0.0/16 --max-requests-inflight=1000

7月 13 16:46:19 ceph01 kube-apiserver[13283]: E0713 16:46:19.416994   13283 reflector.go:201] k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion/factory.go:70: Failed to list *api.Secret: the server cannot complete the requested operation at this time, try again later (get secrets)
7月 13 16:46:19 ceph01 kube-apiserver[13283]: E0713 16:46:19.418162   13283 reflector.go:201] k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion/factory.go:70: Failed to list *api.ResourceQuota: the server cannot complete the requested operation at this time, try again later (get resourcequotas)
7月 13 16:47:20 ceph01 kube-apiserver[13283]: E0713 16:47:20.416735   13283 reflector.go:201] k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion/factory.go:70: Failed to list *api.LimitRange: the server cannot complete the requested operation at this time, try again later (get limitranges)
7月 13 16:47:20 ceph01 kube-apiserver[13283]: E0713 16:47:20.416850   13283 reflector.go:201] k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion/factory.go:70: Failed to list *api.Namespace: the server cannot complete the requested operation at this time, try again later (get namespaces)
7月 13 16:47:20 ceph01 kube-apiserver[13283]: E0713 16:47:20.418041   13283 reflector.go:201] k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion/factory.go:70: Failed to list *api.Secret: the server cannot complete the requested operation at this time, try again later (get secrets)
7月 13 16:47:20 ceph01 kube-apiserver[13283]: E0713 16:47:20.420170   13283 reflector.go:201] k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion/factory.go:70: Failed to list *api.ResourceQuota: the server cannot complete the requested operation at this time, try again later (get resourcequotas)
7月 13 16:48:21 ceph01 kube-apiserver[13283]: E0713 16:48:21.417891   13283 reflector.go:201] k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion/factory.go:70: Failed to list *api.LimitRange: the server cannot complete the requested operation at this time, try again later (get limitranges)
7月 13 16:48:21 ceph01 kube-apiserver[13283]: E0713 16:48:21.418711   13283 reflector.go:201] k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion/factory.go:70: Failed to list *api.Namespace: the server cannot complete the requested operation at this time, try again later (get namespaces)
7月 13 16:48:21 ceph01 kube-apiserver[13283]: E0713 16:48:21.419849   13283 reflector.go:201] k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion/factory.go:70: Failed to list *api.Secret: the server cannot complete the requested operation at this time, try again later (get secrets)
7月 13 16:48:21 ceph01 kube-apiserver[13283]: E0713 16:48:21.420954   13283 reflector.go:201] k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion/factory.go:70: Failed to list *api.ResourceQuota: the server cannot complete the requested operation at this time, try again later (get resourcequotas)
```
(2) 从 kubectl get  node  --v=10 命令查看：
```
I0713 16:47:10.921261   16850 request.go:905] Response Body: {"metadata":{},"status":"Failure","message":"The list operation against nodes could not be completed at this time, please try again.","reason":"ServerTimeout","details":{"name":"list","kind":"nodes"},"code":500}
I0713 16:47:10.921294   16850 request.go:996] Response Body: "{\"metadata\":{},\"status\":\"Failure\",\"message\":\"The list operation against nodes could not be completed at this time, please try again.\",\"reason\":\"ServerTimeout\",\"details\":{\"name\":\"list\",\"kind\":\"nodes\"},\"code\":500}\n"
I0713 16:47:10.921634   16850 helpers.go:203] server response object: [{
  "metadata": {},
  "status": "Failure",
  "message": "the server cannot complete the requested operation at this time, try again later (get nodes)",
  "reason": "ServerTimeout",
  "details": {
    "kind": "nodes",
    "causes": [
      {
        "reason": "UnexpectedServerResponse",
        "message": "{\"metadata\":{},\"status\":\"Failure\",\"message\":\"The list operation against nodes could not be completed at this time, please try again.\",\"reason\":\"ServerTimeout\",\"details\":{\"name\":\"list\",\"kind\":\"nodes\"},\"code\":500}"
      }
    ]
  },
  "code": 504
}]
F0713 16:47:10.921670   16850 helpers.go:116] Error from server (ServerTimeout): the server cannot complete the requested operation at this time, try again later (get nodes)
```

#### 1.2 问题解决
主要问题是 kube-apiserver 与 etcd  版本匹配问题，参考链接：  
```
kube-apiserver --storage-backend defaults to etcd3 and hangs if connecting to etcd2 cluster

https://github.com/kubernetes/kubernetes/issues/43634
```
解决方案是修改 kube-apiserver 启动参数指定 etcd 版本：
```
--storage-backend=etcd2
```

