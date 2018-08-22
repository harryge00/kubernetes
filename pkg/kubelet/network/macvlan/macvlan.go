package macvlan

import (
	"fmt"
	"net"
	"strings"

	"github.com/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/libcni"
	"github.com/golang/glog"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"k8s.io/kubernetes/pkg/apis/componentconfig"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/dockertools"
	"k8s.io/kubernetes/pkg/kubelet/network"
	"sort"
	"strconv"
)

const (
	ipAnno    = "annotation.ips"
	maskAnno  = "annotation.mask"
	macPrefix = "02:42"
)

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

type macvlanNetworkPlugin struct {
	network.NoopNetworkPlugin
	macvlanName       string
	host              network.Host
	netdev            string
	typer             string
	dclient           dockertools.DockerInterface
	err               error
	nonMasqueradeCIDR string

	icmpMessage []byte
	hostInterfaceName      string
	mode        string
	mtu         int
}

func NewPlugin(pluginDir string, client dockertools.DockerInterface) network.NetworkPlugin {
	files, err := libcni.ConfFiles(pluginDir)
	if err != nil {
		return nil
	}
	if len(files) == 0 {
		glog.Errorf("No files under macvlan plugin dir: %v", pluginDir)
		return nil
	}
	macvlanPlug := macvlanNetworkPlugin{
		macvlanName: network.MacvlanPluginName,
		dclient:     client,
	}
	sort.Strings(files)
	for _, confFile := range files {
		conf, err := libcni.ConfFromFile(confFile)
		if err != nil {
			glog.Warningf("Error loading macvlan config file %s: %v", confFile, err)
			continue
		}
		macvlanPlug.mode = conf.Network.Type
		macvlanPlug.hostInterfaceName = conf.Network.Name
		break
	}
	pingMessage := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 1, Seq: 1,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}
	macvlanPlug.icmpMessage, err = pingMessage.Marshal(nil)
	if err != nil {
		glog.Error(err)
	}

	return &macvlanPlug
}

func (plugin *macvlanNetworkPlugin) Init(host network.Host, hairpinMode componentconfig.HairpinMode, nonMasqueradeCIDR string, mtu int) error {
	plugin.host = host
	plugin.mtu = mtu

	plugin.nonMasqueradeCIDR = nonMasqueradeCIDR
	pluginConf := fmt.Sprintf("macvlan mode: %v, hostInterfaceName: %v, mtu: %v, macvlanName: %s, host: %v, netdev: %s, typer: %s, non-masquerade-cidr: %s ",
		plugin.mode, plugin.hostInterfaceName, plugin.mtu, plugin.macvlanName, plugin.host, plugin.netdev, plugin.typer, plugin.nonMasqueradeCIDR)
	glog.Info("Macvlan config: ", pluginConf)

	return nil
}

func (plugin *macvlanNetworkPlugin) Name() string {
	return plugin.macvlanName
}

func getNetCardAndType(labels map[string]string) (err error, dev, ip, mask string) {
	if labels[ipAnno] == "" || labels[maskAnno] == "" {
		err = fmt.Errorf("No network label")
		return
	}
	ips := strings.Split(labels[ipAnno], "-")
	if len(ips) != 2 {
		err = fmt.Errorf("IP label length error")
		return
	}
	dev = ips[0]
	ip = ips[1]
	masks := strings.Split(labels[maskAnno], "-")
	if len(masks) != 2 {
		err = fmt.Errorf("Mask label length error")
		return
	}
	mask = masks[1]
	return
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

	// If shouldChangeDefaultGateway is true, we use the macvlan iface as the default for routing
	shouldChangeDefaultGateway := annotations[network.ChangeGateway] == "true"
	iface, err := plugin.createMacvlan(ips[0], netNamespace, parsedIP, mask, ipv4, routes, shouldChangeDefaultGateway)
	if err != nil {
		return fmt.Errorf("Macvlan Failed to add ifname to netns %v", err)
	}
	glog.V(6).Infof("Successfully SetUpPod for %v/%v. Iface：%v", namespace, name, iface)
	return nil
}

func deleteLink(linkName string) error {
	macvlanIface, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}
	return netlink.LinkDel(macvlanIface)
}

// TearDownPod return no error because the macvlan will be deleted if the namespace removed
func (plugin *macvlanNetworkPlugin) TearDownPod(namespace string, name string, id kubecontainer.ContainerID) error {
	glog.V(6).Infof("TearDownPod for %v/%v %v", namespace, name, id.ID)
	glog.Flush()
	containerinfo, err := plugin.dclient.InspectContainer(id.ID)
	if err != nil {
		// If container does not exist, no need to TearDown.
		glog.Errorf("Failed to get container struct info %v", err)
		return nil
	}

	if containerinfo.State.Status == "exited" || containerinfo.State.Running == false {
		return nil
	}
	// ipArr like:
	err, netdev, netIP, _ := getNetCardAndType(containerinfo.Config.Labels)

	glog.V(6).Infof("netdev: %v, ip: %v, err: %v", netdev, netIP, err)
	if err != nil {
		return nil
	}

	err = ns.WithNetNSPath(containerinfo.NetworkSettings.SandboxKey, func(_ ns.NetNS) error {
		return deleteLink(netdev)
	})

	if err == nil {
		glog.V(6).Infof("Successfully deleteLink %v", netdev)
	} else {
		glog.Errorf("Failed to TearDownPod: %v", err)
	}


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
	// We do NOT want to replace Pod IP with macvlan IP. So we just return the original pod IP.
	status := network.PodNetworkStatus{}
	status.IP = net.ParseIP(c.NetworkSettings.IPAddress)

	err, netdev, ip, mask := getNetCardAndType(c.Config.Labels)
	glog.V(6).Infof("netdev: %v, ip: %v, mask: %v, err: %v", netdev, ip, mask, err)
	if err != nil {
		return &status, nil
	}

	if c.State.Status == "exited" || c.NetworkSettings.MacAddress == "" {
		return &status, nil
	}

	netStr := ip + "/" + mask
	expectedIPAddr, err := netlink.ParseAddr(netStr)
	if err != nil {
		return nil, err
	}

	err = ns.WithNetNSPath(c.NetworkSettings.SandboxKey, func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(netdev)
		if err != nil {
			return err
		}
		ipaddrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return err
		}
		glog.Info(ipaddrs)
		for _, ipaddr := range ipaddrs {
			if expectedIPAddr.Equal(ipaddr) {
				glog.Infof("Got the addr: %v %v", ipaddr, expectedIPAddr)
				return nil
			}
		}
		return fmt.Errorf("IP not found")
	})

	if err != nil {
		glog.Errorf("GetPodNetworkStatus %v/%v error: %v", namespace, name, err)
	}

	return &status, nil
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

func (plugin *macvlanNetworkPlugin) createMacvlan(netdev string, netNamespace ns.NetNS, ipv4 net.IP, mask int, ipv4str string, routes []string, shouldChangeDefaultGateway bool) (*current.Interface, error) {
	macvlan := &current.Interface{}
	mode, err := modeFromString(plugin.mode)
	if err != nil {
		return nil, err
	}
	m, err := netlink.LinkByName(plugin.hostInterfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup hostInterfaceName %q: %v", plugin.hostInterfaceName, err)
	}

	// We generate a random veth name to avoid name collision (many "eth1" on the same host)
	randomVethName, err := ip.RandomVethName()
	if err != nil {
		glog.Errorf("failed to random name %v", err)
		return nil, err
	}
	glog.V(6).Infof("randomVethName %v for ip: %v", randomVethName, ipv4str)
	mv := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{
			MTU:         plugin.mtu,
			Name:        randomVethName,
			ParentIndex: m.Attrs().Index,
			Namespace:   netlink.NsFd(int(netNamespace.Fd())),
		},
		Mode: mode,
	}

	if err := netlink.LinkAdd(mv); err != nil {
		return nil, fmt.Errorf("failed to create macvlan: %v", err)
	}

	err = netNamespace.Do(func(_ ns.NetNS) error {
		err := ip.RenameLink(randomVethName, netdev)
		macvlan.Name = netdev

		if err != nil {
			_ = netlink.LinkDel(mv)
			return fmt.Errorf("failed to rename macvlan to %q: %v", netdev, err)
		}

		macvlanIface, err := netlink.LinkByName(netdev)
		if err != nil {
			glog.Infof("failed to get link by name: %v", netdev)
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

		// No need to try. Because the whole function will be retried if SetUpPod failed.
		err = netlink.LinkSetUp(macvlanIface)

		if err != nil {
			glog.Warningf("failed to set link up %v", err)
			delLinkErr := netlink.LinkDel(mv)
			glog.V(6).Infof("delLinkErr: %v", delLinkErr)
			return err
		}

		ipMask := net.CIDRMask(mask, 32)
		macvlanNet := &net.IPNet{IP: ipv4, Mask: ipMask}

		ipaddr := &netlink.Addr{IPNet: macvlanNet}

		err = netlink.AddrAdd(macvlanIface, ipaddr)

		if err != nil {
			return err
		}

		// If macvlan IP is 172.25.12.8/16, gateway should be 172.25.0.1
		macvlanGateway := ipv4.Mask(ipMask)
		macvlanGateway[3]++

		// For wanghui TEST
		if strings.HasPrefix(ipv4str, "10.35.48.18") {
			macvlanGateway = net.ParseIP("10.35.51.254")
			shouldChangeDefaultGateway = true
		}
		if shouldChangeDefaultGateway {
			err = netlink.RouteReplace(&netlink.Route{
				LinkIndex: macvlanIface.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Gw:        macvlanGateway,
			})
			if err != nil {
				glog.Warningf("Failed to replace default gateway for %v: %v", ipv4, err)
				return err
			}
		}

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
		err = plugin.pingGateWay(macvlanGateway.String())
		if err != nil {
			glog.Error(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return macvlan, nil
}

// To flush the ARP cache, ping the gateway. So the switch will know macvlanIP <-> Mac address.
func (plugin *macvlanNetworkPlugin) pingGateWay(gateWayIP string) error {
	conn, err := net.Dial("ip4:icmp", gateWayIP)
	if err != nil {
		return err
	}

	_, err = conn.Write(plugin.icmpMessage)
	conn.Close()
	// No need to wait for ICMP reply.

	return err
}
