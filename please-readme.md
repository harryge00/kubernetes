####1.6.7版本的update-all.sh与以往很不同．运行之前需要去pull reg.dhdc.com/dhc_cloud/kube-cross:v1.7.6-k8s1.6-0,
然后改tag为：gcr.io/google_containers/kube-cross:v1.7.6-k8s1.6-0;
####将vendor下的文件copy一份到与k8s.io目录同级下
####注释脚本 hack/godep-restore.sh: GOPATH=${GOPATH}:${KUBE_ROOT}/staging godep restore "$@"
####设置GOPATH和KUBE_ROOT环境变量
####执行bash hack/update-all.sh -v -a, 查看报错日志

