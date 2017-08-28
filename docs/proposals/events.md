### rc event

状态转换图：

RCPodAdd(controller) ---->>>> RCPodReady(kubelet) ---->>>> RCPodUnReady(kubelet)--->>>RcPodReady(kubelet) ---->>>> RcPodDelete(kubeclient)

为什么不在controller里面统一做?因为contoller总归是无状态的,前台要求event 100%正确,不能重发,
那么通过本地缓存的方法是行不通的,所以必须把event分开,放到不同的主键中去,才能做到重启无重发,状态一致.
kubelet是直接能感知Pod是不是ready的,当pause容器挂掉,rc是无从得知的,如果通过比较container id,将会从走本地缓存的老路,
引发一系列问题,实际上最好通过新的api资源一劳永逸解决这些问题.

### job event

JobPodAdd(controller) ---->>>> JobPodReady(kubelet) ---->>>> JobPodUnReady(kubelet)--->>>JobPodReady(kubelet) ---->>>> JobPodDelete(kubeclient)

同上

### autoscale event

scalebegin ---->>>> scaleend
scalebegin ---->>>> scalebegin ---->>>> scaleend

两种状态变迁.因为autoscale可能是连续变迁的,所以存在多个scalebegin对应一个scaleend.

scale event是通过本地缓存做的,因为状态只有两种,即使重启多发也不会影响
如果在scalebegin前断电,此时未触发scale,则不会有scalebegin,而只有scaleend,此时autoscale已经结束,因此不影响前台状态
如果scalebegin后,scaleend前断电,状态就会是scalebegin ---->>>> scalebegin ---->>>> scaleend,属于正常状态的情况.

WARNING: scaleend event依赖于rc status,如果此时client出错,可能错过scaleend event.


### WARNING

因为前台非常依赖于event,和后台逻辑耦合非常紧,取得event后,立马删除之,(实际没有必要,event会合并)所以event出现问题,前台也跟着出错.希望前台做容错.