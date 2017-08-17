## API设计

社区原生job API是这样：
```
apiVersion: batch/v1
kind: Job
metadata:
  # Unique key of the Job instance
  name: example-job-fail
spec:
  completions: 2
  parallelism: 2
  template:
    metadata:
      name: example-job-fail
    spec:
      containers:
      - name: example-fail
        image: reg.dhdc.com/luobingli/heapster:v1.2
        imagePullPolicy: IfNotPresent
      # Do not restart containers after they exit
      restartPolicy: Never

```
新特性在spec字段加入了activeDeadlineCount,failedDeleteAll.这两个字段不是必须的.activeDeadlineCount作用是job失败的
pod个数超过此字段的个数时,认定此job失败.failedDeleteAll的作用是在job失败的时候删除job生成的所以pod.
新的api如下：
```
apiVersion: batch/v1
kind: Job
metadata:
  # Unique key of the Job instance
  name: example-job-fail
spec:
  completions: 2
  parallelism: 2
  activeDeadlineCount: 10
  failedDeleteAll: true
  template:
    metadata:
      name: example-job-fail
    spec:
      containers:
      - name: example-fail
        image: reg.dhdc.com/luobingli/heapster:v1.2
        imagePullPolicy: IfNotPresent
      # Do not restart containers after they exit
      restartPolicy: Never
```

### 示例
1.job.yaml:
```
apiVersion: batch/v1
kind: Job
metadata:
  # Unique key of the Job instance
  name: example-job-fail
spec:
  completions: 2
  parallelism: 2
  activeDeadlineCount: 10
  failedDeleteAll: true
  template:
    metadata:
      name: example-job-fail
    spec:
      containers:
      - name: example-fail
        image: reg.dhdc.com/luobingli/heapster:v1.2
        imagePullPolicy: IfNotPresent
      # Do not restart containers after they exit
      restartPolicy: Never
```

2.create:  kubectl create -f job.yaml
3.中间状态:
```
kubectl get pod -a

example-job-fail-00pzg   0/1       ContainerCreating   0          1s
example-job-fail-3hc3x   0/1       Error               0          8s
example-job-fail-4wp0c   0/1       Error               0          4s
example-job-fail-kwwmt   0/1       ContainerCreating   0          4s
example-job-fail-lqpws   0/1       Error               0          8s
```

```
kubectl get pod -a

example-job-fail-00pzg   0/1       Error               0          13s
example-job-fail-3hc3x   0/1       Error               0          20s
example-job-fail-40r2c   0/1       Error               0          11s
example-job-fail-4wp0c   0/1       Error               0          16s
example-job-fail-596nt   0/1       Error               0          5s
example-job-fail-8f2xf   0/1       Error               0          7s
example-job-fail-kwwmt   0/1       Error               0          16s
example-job-fail-lqpws   0/1       Error               0          20s
example-job-fail-q91z3   0/1       Error               0          9s
example-job-fail-tv3rm   0/1       ContainerCreating   0          1s
example-job-fail-zdnkg   0/1       ContainerCreating   0          3s
```

```
kubectl get pod -a

example-job-fail-00pzg   0/1       Terminating         0          14s
example-job-fail-3hc3x   0/1       Terminating         0          21s
example-job-fail-40r2c   0/1       Terminating         0          12s
example-job-fail-4wp0c   0/1       Terminating         0          17s
example-job-fail-596nt   0/1       Terminating         0          6s
example-job-fail-8f2xf   0/1       Terminating         0          8s
example-job-fail-kwwmt   0/1       Terminating         0          17s
example-job-fail-lqpws   0/1       Terminating         0          21s
example-job-fail-n7990   0/1       ContainerCreating   0          0s
example-job-fail-q91z3   0/1       Terminating         0          10s
example-job-fail-tv3rm   0/1       Terminating         0          2s
example-job-fail-zdnkg   0/1       Terminating         0          4s
```

```
kubectl get pod -a

No resources found.
```

4.job最终状态：
```
kubectl describe job job-example

Events:
  FirstSeen	LastSeen	Count	From		SubObjectPath	Type		Reason			Message
  ---------	--------	-----	----		-------------	--------	------			-------
  3m		3m		1	job-controller			Normal		SuccessfulCreate	Created pod: example-job-fail-3hc3x
  3m		3m		1	job-controller			Normal		SuccessfulCreate	Created pod: example-job-fail-lqpws
  3m		3m		1	job-controller			Normal		SuccessfulCreate	Created pod: example-job-fail-kwwmt
  3m		3m		1	job-controller			Normal		SuccessfulCreate	Created pod: example-job-fail-4wp0c
  3m		3m		1	job-controller			Normal		SuccessfulCreate	Created pod: example-job-fail-00pzg
  3m		3m		1	job-controller			Normal		SuccessfulCreate	Created pod: example-job-fail-40r2c
  2m		2m		1	job-controller			Normal		SuccessfulCreate	Created pod: example-job-fail-q91z3
  2m		2m		1	job-controller			Normal		SuccessfulCreate	Created pod: example-job-fail-8f2xf
  2m		2m		1	job-controller			Normal		SuccessfulCreate	Created pod: example-job-fail-596nt
  2m		2m		1	job-controller			Normal		SuccessfulDelete	Deleted pod: example-job-fail-tv3rm
  2m		2m		3	job-controller			Normal		SuccessfulCreate	(events with common reason combined)
  2m		2m		1	job-controller			Normal		SuccessfulDelete	Deleted pod: example-job-fail-q91z3
  2m		2m		1	job-controller			Normal		SuccessfulDelete	Deleted pod: example-job-fail-3hc3x
  2m		2m		1	job-controller			Normal		SuccessfulDelete	Deleted pod: example-job-fail-596nt
  2m		2m		1	job-controller			Normal		SuccessfulDelete	Deleted pod: example-job-fail-8f2xf
  2m		2m		1	job-controller			Normal		SuccessfulDelete	Deleted pod: example-job-fail-n7990
  2m		2m		1	job-controller			Normal		SuccessfulDelete	Deleted pod: example-job-fail-lqpws
  2m		2m		1	job-controller			Normal		SuccessfulDelete	Deleted pod: example-job-fail-kwwmt
  2m		2m		1	job-controller			Normal		SuccessfulDelete	Deleted pod: example-job-fail-zdnkg
  2m		2m		1	job-controller			Normal		DeadlineCountExceeded	Job's pod failed count larger than specified DeadlineCount
  2m		2m		3	job-controller			Normal		SuccessfulDelete	(events with common reason combined)
```