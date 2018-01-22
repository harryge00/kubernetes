package macvlan

import (
	"fmt"
	"net"
	"strings"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"k8s.io/kubernetes/pkg/kubelet/dockershim/libdocker"

	"github.com/golang/glog"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/network"
	"k8s.io/utils/exec"
	"strconv"
	"sync"
)

const (
	gw          = "66.1.1.254"
	macPrefix   = "02:42"
)

type NetConf struct {
	NetCardName string `json:"master"`
	MacvlanMode   string `json:"mode"`
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

type macvlanNetworkPlugin struct {
	network.NoopNetworkPlugin
	netconf     NetConf
	macvlanName string
	host        network.Host
	netdev      string
	typer       string
	ipv4        string
	dclient     *libdocker.Interface
	err         error
	ip1181      net.IP
	mask1181    int
	ip1199      net.IP
	mask1199    int
}

func NewPlugin(client *libdocker.Interface, host network.Host, netcardName string, mode string, mtu int) network.NetworkPlugin {
	glog.Infof("Macvlan plugin initializing with %v %v %v", netcardName, mode)
	plugin := &macvlanNetworkPlugin{
		macvlanName: "macvlan",
		dclient: client,
		host: host,
	}
	plugin.netconf = NetConf{
		NetCardName: netcardName,
		MTU:    mtu,
		MacvlanMode:   mode,
	}

	// TODO: move default mask to config
	plugin.ip1181 = net.ParseIP("10.30.96.0")
	plugin.mask1181 = 21
	plugin.ip1199 = net.ParseIP("172.25.0.0")
	plugin.mask1199 = 16

	return plugin
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
	if annotations[network.NetworkKey] == "" || annotations[network.IPAnnotationKey] == "" ||
		annotations[network.MaskAnnotationKey] == "" {
		glog.V(6).Info("Not enough annotation of macvlan SetUpPod: %v", annotations)
		return nil
	}

	netdev := strings.Split(annotations[network.NetworkKey], "-")
	if len(netdev) != 2 {
		return fmt.Errorf("Cannot get netdev from: %v", annotations)
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

	glog.V(6).Infof("SetUpPod %v/%v", namespace, name)
	containerinfo, err := (*plugin.dclient).InspectContainer(id.ID)
	if err != nil {
		glog.Errorf("Macvlan failed to get container struct info %v", err)
		return err
	}
	//we supposed netns link have been made for `ln -s /var/run/docker/netns /var/run` before add this second netType
	fullnetns := containerinfo.NetworkSettings.SandboxKey
	netns, err := ns.GetNS(fullnetns)
	if err != nil {
		return fmt.Errorf("Macvlan failed to open netns %v: %v", netns, err)
	}
	defer netns.Close()

	err = plugin.cmdAdd(netdev[0], netns, parsedIP, gw, mask, ipv4)
	if err != nil {
		return fmt.Errorf("Macvlan Failed to add ifname to netns %v", err)
	}
	glog.V(6).Infof("Successfully SetUpPod for %v/%v", namespace, name)
	return nil
}

func (plugin *macvlanNetworkPlugin) TearDownPod(namespace string, name string, id kubecontainer.ContainerID) error {
	glog.V(6).Infof("TearDownPod for %v/%v %v", namespace, name, id.ID)
	containerinfo, err := (*plugin.dclient).InspectContainer(id.ID)
	if err != nil {
		glog.Errorf("Failed to get container struct info %v", err)
		return err
	}
	err, netdev := getNetCardAndType(containerinfo.Config.Labels)
	if err != nil {
		return fmt.Errorf("Cannot get labels from %v", err)
	}
	fullnetns := containerinfo.NetworkSettings.SandboxKey
	netns, err := ns.GetNS(fullnetns)
	if err != nil {
		glog.Errorf("failed to open netns %q: %v", netns, err)
		return fmt.Errorf("failed to open netns %q: %v", netns, err)
	}
	defer netns.Close()
	// IP is released by controllers now.
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
	c, err := (*plugin.dclient).InspectContainer(id.ID)
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
	//var mask int
	//strArr := strings.Split(fields[3], "/")
	//if len(strArr) == 2 {
	//	mask, _ = strconv.Atoi(strArr[1])
	//}
	//return &network.PodNetworkStatus{IP: ip, Mask: mask}, nil
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

func (plugin *macvlanNetworkPlugin) createMacvlan(ifName string, netns ns.NetNS, ipv4 net.IP, gw string, mask int, ipv4str string) (*current.Interface, error) {

	macvlan := &current.Interface{}
	mode, err := modeFromString(plugin.netconf.MacvlanMode)
	if err != nil {
		return nil, err
	}
	m, err := netlink.LinkByName(plugin.netconf.NetCardName)
	if err != nil {
		return nil, fmt.Errorf("Peiqi Macvlan failed to lookup master %q: %v", plugin.netconf.NetCardName, err)
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

		// FIXME(Peiqi): generate MACADDR to fix mac ip pair.
		MacAddr, err := generateMacAddr(ipv4str)
		if err == nil {
			err = netlink.LinkSetHardwareAddr(iface, MacAddr)
			if err != nil {
				glog.Errorf("failed to set macaddress %s", err)
				return err
			}
		} else {
			glog.Errorf("failed to generate an macaddress for ipv4")
		}

		err = netlink.LinkSetUp(iface)
		if err != nil {
			glog.Infof("Peiqi Macvlan failed to set link up %v", err)
			return err
		}

		netv4 := &net.IPNet{IP: ipv4, Mask: net.CIDRMask(mask, 32)}

		ipaddr := &netlink.Addr{IPNet: netv4}
		err = netlink.AddrAdd(iface, ipaddr)
		if err != nil {
			glog.Infof("Peiqi Macvlan failed to add ipv4 address %v", err)
			return err
		}

		// ip route add x.x.x.x/16 dev ethx
		err = netlink.RouteAdd(&netlink.Route{
			LinkIndex: iface.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       netv4,
		})
		if err != nil {
			glog.Errorf("Peiqi Macvlan failed to add ethernet route rules: %v", err)
		}
		// 10.30.99.* is from 1181
		// Add route to 1199 (172.25.*.*)
		if strings.HasPrefix(ipv4str, "10.30.99") {
			dst1199 := &net.IPNet{
				IP:   plugin.ip1199,
				Mask: net.CIDRMask(plugin.mask1199, 32),
			}
			glog.V(6).Infof("RouteAdd 1199 %v", dst1199.String())
			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: iface.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Dst:       dst1199,
			})
			if err != nil {
				glog.Errorf("Macvlan failed to add 1199 route rules: %v", err)
			}
		} else if strings.HasPrefix(ipv4str, "172.25.12") {
			// 172.25.12.* is from 1199
			// Add route to 1181 (10.30.99.*)

			dst1181 := &net.IPNet{
				IP:   plugin.ip1181,
				Mask: net.CIDRMask(plugin.mask1181, 32),
			}
			glog.V(6).Infof("RouteAdd 1181 %v", dst1181.String())
			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: iface.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Dst:       dst1181,
			})
			if err != nil {
				glog.Errorf("Macvlan failed to add 1181 route rules: %v", err)
			}
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

func (plugin *macvlanNetworkPlugin) cmdAdd(ifname string, netns ns.NetNS, ipv4 net.IP, gw string, mask int, ipv4str string) error {
	iface, err := plugin.createMacvlan(ifname, netns, ipv4, gw, mask, ipv4str)
	if err != nil {
		glog.Errorf("Peiqi Macvlan Failed to create macvlan %v", err)
		return err
	}
	glog.V(6).Infof("Peiqi Macvlan interface getted is %v", iface)
	return nil
}

func cmdDel(ifname string, netns string) error {
	// There is a netns so try to clean up. Delete can be called multiple times
	// so don't return an error if the device is already removed.
	glog.V(6).Infof("del net card : %v/%v", ifname, netns)
	err := ns.WithNetNSPath(netns, func(_ ns.NetNS) error {
		if _, err := ip.DelLinkByNameAddr(ifname); err != nil {
			glog.Errorf("Failed to DelLinkByNameAddr: %v", err)
			if err != ip.ErrLinkNotFound {
				return err
			}
		}
		return nil
	})
	return err
}
