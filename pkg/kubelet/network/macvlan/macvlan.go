package macvlan

import (
	"bytes"
	"fmt"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net"
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/cni/pkg/types/current"
	"github.com/vishvananda/netlink"

	"k8s.io/kubernetes/pkg/kubelet/network"
	"k8s.io/kubernetes/pkg/util/exec"
	"k8s.io/kubernetes/pkg/apis/componentconfig"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	dockerclient "github.com/fsouza/go-dockerclient"
	"sync"
	"github.com/golang/glog"
)

const (
	gw = "66.1.1.254"
)

type NetConf struct {
	Master string `json:"master"`
	Mode   string `json:"mode"`
	MTU     int   `json:"mtu"`
}

type NetType string
type Typer struct {
	NetType   NetType `json:"nettype"`
}

type Data struct {
	ResInfo  string  `json:"resinfo, omitempty"`
	IP  	 string  `json:"ip, omitempty"`
	Routes[] string  `json:"routes, omitempty"`
	Mask	 int  	 `json:"mask, omitempty"`
}

type DataToDel struct {
	NetType   NetType  `json:"nettype, omitempty"`
	Startip   string   `json:"startip, omitempty"`
	Mask      int      `json:"mask, omitempty"`
}

// NWClient defines information needed for the k8s api client
type NWClient struct {
	baseURL string
	client  *http.Client
}

type macvlanNetworkPlugin struct {
	Mutex       *sync.Mutex
	network.NoopNetworkPlugin
	netconf     NetConf
	macvlanName string
	host        network.Host
	netdev      string
	typer       string
	ipamclient  NWClient
	ipv4        string
	mask        int
	dclient     *dockerclient.Client
	err         error
}

func ProbeNetworkPlugins() []network.NetworkPlugin {
	macvlanPlugins := []network.NetworkPlugin{}
	macvlanPlugins = append(macvlanPlugins, &macvlanNetworkPlugin{macvlanName: "macvlan"})
	return macvlanPlugins
}

func (plugin *macvlanNetworkPlugin) Init(host network.Host, hairpinMode componentconfig.HairpinMode, master string, mode string, addr string, nonMasqueradeCIDR string, mtu int) error {
	//noop
	plugin.Mutex = &sync.Mutex{}
	plugin.host = host
	plugin.macvlanName = "macvlan"
	plugin.netconf = NetConf{
		Master: master,
		MTU:	mtu,
		Mode:	mode,
	}
	plugin.ipamclient = NWClient{
		baseURL: addr,
		client:  &http.Client{},
	}
	plugin.mask = 16
	plugin.dclient, plugin.err = dockerclient.NewClient("unix:///var/run/docker.sock")
	if plugin.err != nil{
		glog.Errorf("Macvlan failed to connect to docker at local host %v", plugin.err)
	}

	return nil
}

func (plugin *macvlanNetworkPlugin) GetterIP(netType string) (string, error){

	//from plugin.typer, plugin.server to get IP and mask
	data := Data{}
	nettyper := NetType(netType)
	typer := Typer{
		NetType: nettyper,
	}
	buf, err := json.Marshal(typer)
	if err != nil {
		glog.Errorf("Macvlan failed to Marshal in GetterIP func, please check %v", err)
		return "", err
	}

	body := bytes.NewBuffer(buf)
	url := plugin.ipamclient.baseURL + "/resource/allot"
	r, err := plugin.ipamclient.client.Post(url, "application/json", body)
	if err != nil {
		glog.Errorf("Macvlan failed to Post in GetterIP func, please check %v", err)
		return "", err
	}

	response, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		glog.Errorf("Macvlan failed to Read in GetterIP func, please check %v", err)
		return "", err
	}

	err = json.Unmarshal(response, &data)
	if err != nil {
		glog.Errorf("Macvlan failed to Unmarshal in GetterIP func, please check %v", err)
		return "", err
	}
	ipv4 := data.IP
	plugin.mask = data.Mask
	glog.Infof("mask %v", data)
	return ipv4, nil
}

func (plugin *macvlanNetworkPlugin) DeleteIP(netType, ipv4 string) error{
	glog.Info("mask %v", plugin.mask)

	datadel := DataToDel{
		NetType: NetType(netType),
		Startip: ipv4,
		Mask:    plugin.mask,
	}
	buf, err := json.Marshal(datadel)
	if err != nil {
		glog.Errorf("Macvlan failed to Marshal in DeleteIP func, please check %v", err)
		return  err
	}

	body := bytes.NewBuffer(buf)
	url := plugin.ipamclient.baseURL + "/resource/delete"
	glog.Infof("deleting ip %v %v", url, datadel)
	r, err := plugin.ipamclient.client.Post(url, "application/json", body)
	if err != nil {
		glog.Errorf("Macvlan failed to Post in Delete func, please check %v", err)
		return  err
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
	if labels["network"] == "" {
		return fmt.Errorf("No network label"), nil
	}
	arr := strings.Split(labels["network"], "-")
	if len(arr) != 2 {
		return fmt.Errorf("Network label length error"), nil
	}
	return nil, arr
}

func (plugin *macvlanNetworkPlugin) SetUpPod(namespace string, name string, id kubecontainer.ContainerID, annotations map[string]string) error {
	glog.Infof("SetUpPod %v/%v", namespace, name)
	containerinfo, err := plugin.dclient.InspectContainer(id.ID)
	if err != nil {
		glog.Errorf("Macvlan failed to get container struct info %v", err)
		return err
	}
	err, netdev := getNetCardAndType(containerinfo.Config.Labels)
	if err != nil {
		return fmt.Errorf("Cannot get netdev from: %v", err)
	}
	//we supposed netns link have been made for `ln -s /var/run/docker/netns /var/run` before add this second netdev
	fullnetns := containerinfo.NetworkSettings.SandboxKey
	netns, err := ns.GetNS(fullnetns)
	if err != nil {
		return fmt.Errorf("Macvlan failed to open netns %q: %v", netns, err)
	}
	defer netns.Close()

	var ipv4 string
	if strings.Contains(annotations["ips"],"none") || strings.Contains(annotations["ips"],"empty") || annotations["ips"] == "" {
		ipv4, err = plugin.GetterIP(netdev[1])
		if err != nil {
			return fmt.Errorf("failed to get ipv4 from ipam in Getter IP %v", err)
		}

	} else {
		ipv4 = strings.Split(annotations["ips"],"-")[1]
	}
	glog.Infof("IPv4 is %s", ipv4)
	parsedIP := net.ParseIP(ipv4)
	if parsedIP == nil {
		return fmt.Errorf("Invalid ip: %s", ipv4)
	}

	// Add ip to annotation
	ips := fmt.Sprintf("%s-%s", netdev[0], ipv4)
	annotations["ips"] = ips

	err = plugin.cmdAdd(netdev[0], netns, parsedIP, gw)
	if err != nil {
		return fmt.Errorf("Macvlan Failed to add ifname to netns %v", err)
	}
	return nil
}

func (plugin *macvlanNetworkPlugin) TearDownPod(namespace string, name string, id kubecontainer.ContainerID) error {
	glog.V(6).Infof("TearDownPod for %v/%v %v", namespace, name, id.ID)
	containerinfo, err := plugin.dclient.InspectContainer(id.ID)
	if err != nil{
		glog.Errorf("Failed to get container struct info %v", err)
		return err
	}
	glog.Info(containerinfo)
	err, netdev := getNetCardAndType(containerinfo.Config.Labels)
	if err != nil {
		return fmt.Errorf("Cannot get labels from %v", err)
	}
	//we supposed netns link have been made for `ln -s /var/run/docker/netns /var/run` before add this second netdev
	fullnetns := containerinfo.NetworkSettings.SandboxKey
	netns, err := ns.GetNS(fullnetns)
	if err != nil {
		glog.Errorf("failed to open netns %q: %v", netns, err)
		return fmt.Errorf("failed to open netns %q: %v", netns, err)
	}
	defer netns.Close()
	status, err := plugin.GetPodNetworkStatus(namespace, name, id)
	if err != nil {
		glog.Errorf("failed to get pod network status during pod teardown %v: %v", status, err)
		return fmt.Errorf("failed to get pod network status during pod teardown %v: %v", status, err)
	}
	err = plugin.DeleteIP(netdev[1], status.IP.String())
	if err != nil {
		glog.Errorf("Failed to delete IP from netns %v", err)
		return fmt.Errorf("Failed to delete IP from netns %v", err)
	}
	err = cmdDel(netdev[0], fullnetns)
	if err != nil {
		glog.Errorf("Failed to delete ifname from netns %v", err)
		return fmt.Errorf("Failed to delete ifname from netns %v", err)
	}
	glog.V(6).Infof("Successfully deletes macvlan netcard %v/%v %v", namespace, name, id.ID)
	return nil

}

//if configured double net dev, we should to check the pod status for second net card
func (plugin *macvlanNetworkPlugin) GetPodNetworkStatus(namespace string, name string, id kubecontainer.ContainerID) (*network.PodNetworkStatus, error) {
	glog.Infof("GetPodNetworkStatus %v/%v %v", namespace, name, id.ID)
	c, err := plugin.dclient.InspectContainer(id.ID)
	if err != nil{
		glog.Errorf("Failed to get container struct info %v", err)
		return nil, err
	}
	err, netdev := getNetCardAndType(c.Config.Labels)
	glog.Infof("netdev:%v", netdev)
	if err != nil {
		return nil, fmt.Errorf("Cannot get netdev from %v", err)
	}
	netnsPath := fmt.Sprintf("/proc/%v/ns/net", c.State.Pid)

	cmd := fmt.Sprintf("nsenter --net=%s -F -- ip -o -4 addr show dev %s scope global", netnsPath, netdev[0])
	glog.Info(cmd)
	output, err := exec.New().Command("/bin/sh", "-c", cmd).CombinedOutput()
	glog.Info(string(output))
	if err != nil {
		return nil, fmt.Errorf("Peiqi Macvlan Unexpected command output %s with error: %v", output, err)
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("Peiqi Macvlan Unexpected command output %s", output)
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 4 {
		return nil, fmt.Errorf("Peiqi Macvlan Unexpected address output %s ", lines[0])
	}
	ip, _, err := net.ParseCIDR(fields[3])
	if err != nil {
		return nil, fmt.Errorf("Peiqi Macvlan failed to parse ip from output %s due to %v", output, err)
	}
	return &network.PodNetworkStatus{IP: ip}, nil
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

func (plugin *macvlanNetworkPlugin) createMacvlan(ifName string, netns ns.NetNS, ipv4 net.IP, gw string) (*current.Interface, error) {

	macvlan := &current.Interface{}
	mode, err := modeFromString(plugin.netconf.Mode)
	if err != nil {
		return nil, err
	}
	m, err := netlink.LinkByName(plugin.netconf.Master)
	if err != nil {
		return nil, fmt.Errorf("Peiqi Macvlan failed to lookup master %q: %v", plugin.netconf.Master, err)
	}

	tmpName, err := ip.RandomVethName()
	if err != nil {
		glog.Errorf("Peiqi Macvlan failed to random name %v", err)
		return nil, err
	}

	mv := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{
			MTU:         plugin.netconf.MTU,
			Name:        tmpName,
			ParentIndex: m.Attrs().Index,
			Namespace:   netlink.NsFd(int(netns.Fd())),
		},
		Mode: mode,
	}

	if err := netlink.LinkAdd(mv); err != nil {
		return nil, fmt.Errorf("Peiqi Macvlan failed to create macvlan: %v", err)
	}

	err = netns.Do(func(_ ns.NetNS) error {
		err := ip.RenameLink(tmpName, ifName)
		macvlan.Name = ifName

		if err != nil {
			_ = netlink.LinkDel(mv)
			return fmt.Errorf("Peiqi Macvlan failed to rename macvlan to %q: %v", ifName, err)
		}

		iface, err := netlink.LinkByName(ifName)
		if err != nil {
			glog.Infof("Peiqi Macvlan failed to get link by name: %v", ifName)
			return err
		}

		err = netlink.LinkSetUp(iface)
		if err != nil {
			glog.Infof("Peiqi Macvlan failed to set link up %v", err)
			return err
		}

		netv4 := &net.IPNet{IP: ipv4, Mask: net.CIDRMask(plugin.mask, 32)}

		ipaddr := &netlink.Addr{IPNet: netv4}
		err = netlink.AddrAdd(iface, ipaddr)
		if err != nil {
			glog.Infof("Peiqi Macvlan failed to add ipv4 address %v", err)
			return err
		}

		// ip route add x.x.x.x/16 dev ethx
		err = netlink.RouteAdd(&netlink.Route{
			LinkIndex:  iface.Attrs().Index,
			Scope:      netlink.SCOPE_UNIVERSE,
			Dst:        netv4,
		})
		if err != nil {
			glog.Infof("Peiqi Macvlan failed to add ethernet route rules: %v", err)
		}

		contMacvlan, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("Peiqi Macvlan failed to refetch macvlan %q: %v", ifName, err)
		}
		macvlan.Mac = contMacvlan.Attrs().HardwareAddr.String()
		macvlan.Sandbox = netns.Path()

		return nil
	})
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("nsenter --net=%s -F -- ip -o -4 addr show", netns.Path())
	glog.Info(cmd)
	output, _ := exec.New().Command("/bin/sh", "-c", cmd).CombinedOutput()
	glog.Info(string(output))
	return macvlan, nil
}

func (plugin *macvlanNetworkPlugin) cmdAdd(ifname string, netns ns.NetNS, ipv4 net.IP, gw string) error {
	iface, err := plugin.createMacvlan(ifname, netns, ipv4, gw)
	if err != nil{
		glog.Errorf("Peiqi Macvlan Failed to create macvlan %v", err)
		return err
	}
	glog.Infof("Peiqi Macvlan interface getted is %v", iface)
	return nil
}

func cmdDel(ifname string, netns string) error {
	// There is a netns so try to clean up. Delete can be called multiple times
	// so don't return an error if the device is already removed.
	glog.Infof("del net card : %v/%v", ifname, netns)
	err := ns.WithNetNSPath(netns, func(_ ns.NetNS) error {
		if _, err := ip.DelLinkByNameAddr(ifname, netlink.FAMILY_V4); err != nil {
			glog.Errorf("Failed to DelLinkByNameAddr: %v", err)
			if err != ip.ErrLinkNotFound {
				return err
			}
		}
		return nil
	})
	return err
}
