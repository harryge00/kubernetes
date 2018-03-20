package macvlan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"github.com/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	dockerclient "github.com/fsouza/go-dockerclient"
	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/apis/componentconfig"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/network"
	"k8s.io/kubernetes/pkg/util/exec"
	"strconv"
	"sync"
	"time"
)

const (
	// TODO: configure gateway?
	gw               = "66.1.1.254"
	macPrefix        = "02:42"
)

type NetConf struct {
	Master string `json:"master"`
	Mode   string `json:"mode"`
	MTU    int    `json:"mtu"`
}

type NetType string
type Typer struct {
	NetType NetType `json:"nettype"`
}

type Data struct {
	ResInfo string   `json:"resinfo,omitempty"`
	IP      string   `json:"ip,omitempty"`
	Routes  []string `json:"routes,omitempty"`
	Mask    int      `json:"mask,omitempty"`
}

type DataToDel struct {
	NetType NetType `json:"nettype,omitempty"`
	Startip string  `json:"startip,omitempty"`
	Mask    int     `json:"mask,omitempty"`
}

// NWClient defines information needed for the k8s api client
type NWClient struct {
	baseURL string
	client  *http.Client
}

type macvlanNetworkPlugin struct {
	mutex *sync.Mutex
	network.NoopNetworkPlugin
	netconf           NetConf
	macvlanName       string
	host              network.Host
	netdev            string
	typer             string
	ipamclient        NWClient
	ipv4              string
	dclient           *dockerclient.Client
	err               error
	nonMasqueradeCIDR string
}

func ProbeNetworkPlugins() []network.NetworkPlugin {
	macvlanPlugins := []network.NetworkPlugin{}
	macvlanPlugins = append(macvlanPlugins, &macvlanNetworkPlugin{macvlanName: "macvlan"})
	return macvlanPlugins
}

func (plugin *macvlanNetworkPlugin) Init(host network.Host, hairpinMode componentconfig.HairpinMode, master string, mode string, addr string, nonMasqueradeCIDR string, mtu int) error {
	//noop
	glog.Infof("Macvlan plugin initializing with %v %v %v", master, mode, addr)
	plugin.mutex = &sync.Mutex{}
	plugin.host = host
	plugin.macvlanName = "macvlan"

	plugin.netconf = NetConf{
		Master: master,
		MTU:    mtu,
		Mode:   mode,
	}
	plugin.ipamclient = NWClient{
		baseURL: addr,
		client:  &http.Client{},
	}
	// TODO: move default mask to config
	plugin.dclient, plugin.err = dockerclient.NewClient("unix:///var/run/docker.sock")
	if plugin.err != nil {
		glog.Errorf("Macvlan failed to connect to docker at local host %v", plugin.err)
	}
	plugin.nonMasqueradeCIDR = nonMasqueradeCIDR
	pluginConf := fmt.Sprintf("netconf: %v, macvlanName: %s, host: %v, netdev: %s, typer: %s, non-masquerade-cidr: %s ",
		plugin.netconf, plugin.macvlanName, plugin.host, plugin.netdev, plugin.typer, plugin.nonMasqueradeCIDR)

	glog.Info("Macvlan config: ", pluginConf)

	return nil
}

// Deprecated: Now IPs are got by kube-controller.
func (plugin *macvlanNetworkPlugin) GetterIP(netType string) (ipv4 string, mask int, err error) {
	//from plugin.typer, plugin.server to get IP and mask
	data := Data{}
	nettyper := NetType(netType)
	typer := Typer{
		NetType: nettyper,
	}
	buf, err := json.Marshal(typer)
	if err != nil {
		glog.Errorf("Macvlan failed to Marshal in GetterIP func, please check %v", err)
		return ipv4, mask, err
	}

	body := bytes.NewBuffer(buf)
	url := plugin.ipamclient.baseURL + "/resource/allot"
	r, err := plugin.ipamclient.client.Post(url, "application/json", body)
	if err != nil {
		glog.Errorf("Macvlan failed to Post in GetterIP func, please check %v", err)
		return ipv4, mask, err
	}

	response, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		glog.Errorf("Macvlan failed to Read in GetterIP func, please check %v", err)
		return ipv4, mask, err
	}

	err = json.Unmarshal(response, &data)
	if err != nil {
		glog.Errorf("Macvlan failed to Unmarshal in GetterIP func, please check %v", err)
		return ipv4, mask, err
	}
	ipv4 = data.IP
	return ipv4, data.Mask, nil
}

// Deprecated: Now IPs are released by controllers.
func (plugin *macvlanNetworkPlugin) DeleteIP(netType, ipv4 string, mask int) error {
	glog.Infof("DeleteIP type: %v, ip %v, mask %v", netType, ipv4, mask)

	datadel := DataToDel{
		NetType: NetType(netType),
		Startip: ipv4,
		Mask:    mask,
	}
	buf, err := json.Marshal(datadel)
	if err != nil {
		glog.Errorf("Macvlan failed to Marshal in DeleteIP func, please check %v", err)
		return err
	}

	body := bytes.NewBuffer(buf)
	url := plugin.ipamclient.baseURL + "/resource/delete"
	glog.Infof("deleting ip %v %v", url, datadel)
	r, err := plugin.ipamclient.client.Post(url, "application/json", body)
	if err != nil {
		glog.Errorf("Macvlan failed to Post in Delete func, please check %v", err)
		return err
	}

	defer r.Body.Close()
	switch {
	case r.StatusCode == int(404):
		return fmt.Errorf("page not found")
	case r.StatusCode == int(403):
		return fmt.Errorf("access denied")
	case r.StatusCode != int(200):
		glog.Errorf("GET Status '%s' status code %d \n", r.Status, r.StatusCode)
		return fmt.Errorf("%s", r.Status)
	}
	response, err := ioutil.ReadAll(r.Body)
	if err != nil {
		glog.Errorf("Macvlan failed to Read in DeleteIP response, please check %v", err)
		return nil
	}
	glog.Infof("Successfully release IP:%v ", string(response))
	return nil
}

func (plugin *macvlanNetworkPlugin) Name() string {
	return plugin.macvlanName
}

func getNetCardAndType(labels map[string]string) (error, []string) {
	if labels[network.NetworkKey] == "" {
		return fmt.Errorf("No network label"), nil
	}
	arr := strings.Split(labels[network.NetworkKey], "-")
	if len(arr) != 2 {
		return fmt.Errorf("Network label length error"), nil
	}
	return nil, arr
}

func (plugin *macvlanNetworkPlugin) SetUpPod(namespace string, name string, id kubecontainer.ContainerID, annotations map[string]string) error {
	glog.Infof("SetUpPod %v/%v", namespace, name)

	if annotations[network.IPAnnotationKey] == "" || annotations[network.MaskAnnotationKey] == "" {
		glog.Infof("Not enough annotation of macvlan SetUpPod: %v", annotations)
		return nil
	}

	ipsAnno := annotations[network.IPAnnotationKey]
	ips := strings.Split(ipsAnno, "-")
	if len(ips) != 2 {
		return fmt.Errorf("Invalid ips annotation %v", ips)
	}
	ipv4 := ips[1]
	parsedIP := net.ParseIP(ipv4)
	if parsedIP == nil {
		return fmt.Errorf("Invalid ip: %s", ipv4)
	}

	var mask int
	strMask := strings.Split(annotations[network.MaskAnnotationKey], "-")
	if len(strMask) != 2 {
		return fmt.Errorf("Invalid mask annotation %v", annotations[network.MaskAnnotationKey])
	}
	mask, err := strconv.Atoi(strMask[1])
	if err != nil {
		return fmt.Errorf("Invalid mask annotation %v", annotations[network.MaskAnnotationKey])
	}
	routes := strings.Split(annotations[network.RoutesAnnotationKey], ";")

	containerinfo, err := plugin.dclient.InspectContainer(id.ID)
	if err != nil {
		glog.Errorf("Macvlan failed to get container struct info %v", err)
		return err
	}
	if err != nil {
		return fmt.Errorf("Cannot get netType from: %v", err)
	}
	//we supposed netns link have been made for `ln -s /var/run/docker/netns /var/run` before add this second netType
	netNamespace, err := ns.GetNS(containerinfo.NetworkSettings.SandboxKey)
	if err != nil {
		return fmt.Errorf("Macvlan failed to open netns %v: %v", containerinfo.NetworkSettings.SandboxKey, err)
	}
	defer netNamespace.Close()

	iface, err := plugin.createMacvlan(ips[0], netNamespace, parsedIP, mask, ipv4, routes)
	if err != nil {
		return fmt.Errorf("Macvlan Failed to add ifname to netns %v", err)
	}
	glog.V(6).Infof("Successfully SetUpPod for %v/%v. Iface：%v", namespace, name, iface)
	return nil
}

func (plugin *macvlanNetworkPlugin) TearDownPod(namespace string, name string, id kubecontainer.ContainerID) error {
	glog.V(6).Infof("TearDownPod for %v/%v %v", namespace, name, id.ID)
	containerinfo, err := plugin.dclient.InspectContainer(id.ID)
	if err != nil {
		glog.Errorf("Failed to get container struct info %v", err)
		return err
	}
	err, netdev := getNetCardAndType(containerinfo.Config.Labels)
	if err != nil {
		return fmt.Errorf("Cannot get labels from %v", err)
	}
	netNamespace, err := ns.GetNS(containerinfo.NetworkSettings.SandboxKey)
	if err != nil {
		glog.Errorf("failed to open netns %v: %v", netNamespace, err)
		return fmt.Errorf("failed to open netns %v: %v", netNamespace, err)
	}
	defer netNamespace.Close()
	// IP is released by controllers now.
	err = cmdDel(netdev[0], containerinfo.NetworkSettings.SandboxKey)
	if err != nil {
		glog.Errorf("Failed to delete ifname from netns %v", err)
		return fmt.Errorf("Failed to delete ifname from netns %v", err)
	}
	glog.V(6).Infof("Successfully deletes macvlan netcard %v/%v %v", namespace, name, id.ID)
	return nil

}

// Deprecated
//if configured double net dev, we should to check the pod status for second net card
func (plugin *macvlanNetworkPlugin) GetPodNetworkStatus(namespace string, name string, id kubecontainer.ContainerID) (*network.PodNetworkStatus, error) {
	glog.Infof("GetPodNetworkStatus %v/%v %v", namespace, name, id.ID)
	c, err := plugin.dclient.InspectContainer(id.ID)
	if err != nil {
		glog.Errorf("Failed to get container struct info %v", err)
		return nil, err
	}
	err, netdev := getNetCardAndType(c.Config.Labels)
	glog.Infof("netdev:%v", netdev)
	if err != nil {
		return nil, fmt.Errorf("Cannot get netdev from %v: %v", name, err)
	}
	netnsPath := fmt.Sprintf("/proc/%v/ns/net", c.State.Pid)

	cmd := fmt.Sprintf("nsenter --net=%s -F -- ip -o -4 addr show dev %s scope global", netnsPath, netdev[0])
	glog.Info(cmd)
	output, err := exec.New().Command("/bin/sh", "-c", cmd).CombinedOutput()
	glog.Info(string(output))
	if err != nil {
		return nil, fmt.Errorf("Unexpected command output %s with error: %v", output, err)
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("Unexpected command output %s", output)
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 4 {
		return nil, fmt.Errorf("Unexpected address output %s ", lines[0])
	}
	ip, _, err := net.ParseCIDR(fields[3])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ip from output %s due to %v", output, err)
	}
	var mask int
	strArr := strings.Split(fields[3], "/")
	if len(strArr) == 2 {
		mask, _ = strconv.Atoi(strArr[1])
	}
	return &network.PodNetworkStatus{IP: ip, Mask: mask}, nil
}

func modeFromString(s string) (netlink.MacvlanMode, error) {
	switch s {
	case "", "bridge":
		return netlink.MACVLAN_MODE_BRIDGE, nil
	case "private":
		return netlink.MACVLAN_MODE_PRIVATE, nil
	case "vepa":
		return netlink.MACVLAN_MODE_VEPA, nil
	case "passthru":
		return netlink.MACVLAN_MODE_PASSTHRU, nil
	default:
		return 0, fmt.Errorf("unknown macvlan mode: %q", s)
	}
}

func generateMacAddr(ipv4 string) (net.HardwareAddr, error) {
	macAddr := macPrefix //2 bytes prefix with 4 bytes from ipv4
	ipArrary := strings.Split(ipv4, ".")

	for _, v := range ipArrary {
		q, err := strconv.Atoi(v)
		if err != nil {
			glog.Errorf("failed to translate ipv4 slice into int format %s", err)
			return nil, err
		}
		macAddr = macAddr + fmt.Sprintf(":%02x", q)
	}

	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		glog.Errorf("Failed to parse macaddress, please check the string format is correct, %s", err)
		return nil, err
	}
	return mac, nil
}

func (plugin *macvlanNetworkPlugin) createMacvlan(macvlanName string, netNamespace ns.NetNS, ipv4 net.IP, mask int, ipv4str string, routes []string) (*current.Interface, error) {
	plugin.mutex.Lock()
	defer plugin.mutex.Unlock()

	macvlan := &current.Interface{}
	mode, err := modeFromString(plugin.netconf.Mode)
	if err != nil {
		return nil, err
	}
	m, err := netlink.LinkByName(plugin.netconf.Master)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup master %q: %v", plugin.netconf.Master, err)
	}

	tmpName, err := ip.RandomVethName()
	if err != nil {
		glog.Errorf("failed to random name %v", err)
		return nil, err
	}

	mv := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{
			MTU:         plugin.netconf.MTU,
			Name:        tmpName,
			ParentIndex: m.Attrs().Index,
			Namespace:   netlink.NsFd(int(netNamespace.Fd())),
		},
		Mode: mode,
	}

	if err := netlink.LinkAdd(mv); err != nil {
		return nil, fmt.Errorf("failed to create macvlan: %v", err)
	}

	err = netNamespace.Do(func(_ ns.NetNS) error {
		err := ip.RenameLink(tmpName, macvlanName)
		macvlan.Name = macvlanName

		if err != nil {
			_ = netlink.LinkDel(mv)
			return fmt.Errorf("failed to rename macvlan to %q: %v", macvlanName, err)
		}

		macvlanIface, err := netlink.LinkByName(macvlanName)
		if err != nil {
			glog.Infof("failed to get link by name: %v", macvlanName)
			return err
		}

		// FIXME(Peiqi): generate MACADDR to fix mac ip pair.
		MacAddr, err := generateMacAddr(ipv4str)
		if err == nil {
			err = netlink.LinkSetHardwareAddr(macvlanIface, MacAddr)
			if err != nil {
				glog.Errorf("failed to set macaddress %s", err)
				return err
			}
		} else {
			glog.Errorf("failed to generate an macaddress for ipv4")
		}

		retryInterval := 200 * time.Millisecond
		// Retry to set link up
		for i := 0; i < 3; i++ {
			err = netlink.LinkSetUp(macvlanIface)
			if err == nil {
				break
			}
			glog.Warningf("failed to set link up %v", err)
			time.Sleep(retryInterval)
		}
		if err != nil {
			return err
		}

		ipMask := net.CIDRMask(mask, 32)
		macvlanNet := &net.IPNet{IP: ipv4, Mask: ipMask}

		ipaddr := &netlink.Addr{IPNet: macvlanNet}

		// Retry to add addr
		for i := 0; i < 3; i++ {
			err = netlink.AddrAdd(macvlanIface, ipaddr)
			if err == nil {
				break
			}
			glog.Warningf("failed to add ipv4 %v: %v", ipaddr, err)
			time.Sleep(retryInterval)
		}
		if err != nil {
			return err
		}

		// If macvlan IP is 172.25.12.8/16, gateway should be 172.25.0.1
		macvlanGateway := ipv4.Mask(ipMask)
		macvlanGateway[3]++

		// Add routes to different macvlan networks
		for _, route := range routes {
			_, otherNet, err := net.ParseCIDR(route)
			if err != nil {
				glog.Warningf("Failed to parse route %v for %v", route, ipv4)
				continue
			}
			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: macvlanIface.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Dst:       otherNet,
				Gw:        macvlanGateway,
			})
			if err != nil {
				glog.Warningf("Failed to add route %v for %v: %v", route, ipv4, err)
			}
		}

		macvlan.Mac = macvlanIface.Attrs().HardwareAddr.String()
		macvlan.Sandbox = netNamespace.Path()

		return nil
	})
	if err != nil {
		return nil, err
	}
	return macvlan, nil
}

func cmdDel(macvlanName string, sandBoxKey string) error {
	// There is a netns so try to clean up. Delete can be called multiple times
	// so don't return an error if the device is already removed.
	glog.V(6).Infof("del net card : %v/%v", macvlanName, sandBoxKey)
	err := ns.WithNetNSPath(sandBoxKey, func(_ ns.NetNS) error {
		if _, err := ip.DelLinkByNameAddr(macvlanName, netlink.FAMILY_V4); err != nil {
			glog.Errorf("Failed to DelLinkByNameAddr: %v", err)
			if err != ip.ErrLinkNotFound {
				return err
			}
		}
		return nil
	})
	return err
}
