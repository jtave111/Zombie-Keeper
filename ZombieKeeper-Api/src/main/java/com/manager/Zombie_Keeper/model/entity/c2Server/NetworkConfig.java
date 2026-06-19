package com.manager.Zombie_Keeper.model.entity.c2Server;

import jakarta.persistence.*;

import java.util.List;

@Entity
@Table(name = "tb_network_config")
public class NetworkConfig {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "c_2_server_id")
    private C2Server server;

    private String privateIPV4;
    private String publicIPV4;
    private String privateIPV6;
    private String publicIPV6;
    private String macAddress;

    private String networkInterface; // eth0, wlan0, tun0...

    private String gateway;

    @Column(length = 19)
    private String cidr; // ex: 192.168.1.0/24

    @Column(length = 15)
    private String subnetMask;

    @Column(length = 256)
    private String dnsServers; // comma-separated

    @Column(length = 10)
    private String connectionType; // WIRED, WIRELESS, VPN, TOR

    // Wi-Fi (quando connectionType = WIRELESS)
    private String ssid;
    private String bssid;

    // Proxy
    private Boolean proxyEnabled = false;

    @Column(length = 253)
    private String proxyHost;

    private Integer proxyPort;

    // VPN
    private Boolean vpnEnabled = false;

    @Column(length = 253)
    private String vpnEndpoint;

    @OneToMany(mappedBy = "network")
    private List<PortConfig> ports;

    public C2Server getC2Server() {
        return server;
    }

    public void setC2Server(C2Server server) {
        this.server = server;
    }

    public NetworkConfig() {

    }
    public NetworkConfig(Long id, C2Server server, String privateIPV4, String publicIPV4, String privateIPV6,
                         String publicIPV6, String macAddress, String networkInterface, String gateway, String cidr,
                         String subnetMask, String dnsServers, String connectionType, String ssid, String bssid,
                         Boolean proxyEnabled, String proxyHost, Integer proxyPort, Boolean vpnEnabled,
                         String vpnEndpoint, List<PortConfig> ports) {
        this.id = id;
        this.server = server;
        this.privateIPV4 = privateIPV4;
        this.publicIPV4 = publicIPV4;
        this.privateIPV6 = privateIPV6;
        this.publicIPV6 = publicIPV6;
        this.macAddress = macAddress;
        this.networkInterface = networkInterface;
        this.gateway = gateway;
        this.cidr = cidr;
        this.subnetMask = subnetMask;
        this.dnsServers = dnsServers;
        this.connectionType = connectionType;
        this.ssid = ssid;
        this.bssid = bssid;
        this.proxyEnabled = proxyEnabled;
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
        this.vpnEnabled = vpnEnabled;
        this.vpnEndpoint = vpnEndpoint;
        this.ports = ports;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public C2Server getServer() {
        return server;
    }

    public void setServer(C2Server server) {
        this.server = server;
    }

    public String getPrivateIPV4() {
        return privateIPV4;
    }

    public void setPrivateIPV4(String privateIPV4) {
        this.privateIPV4 = privateIPV4;
    }

    public String getPublicIPV4() {
        return publicIPV4;
    }

    public void setPublicIPV4(String publicIPV4) {
        this.publicIPV4 = publicIPV4;
    }

    public String getPrivateIPV6() {
        return privateIPV6;
    }

    public void setPrivateIPV6(String privateIPV6) {
        this.privateIPV6 = privateIPV6;
    }

    public String getPublicIPV6() {
        return publicIPV6;
    }

    public void setPublicIPV6(String publicIPV6) {
        this.publicIPV6 = publicIPV6;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    public String getNetworkInterface() {
        return networkInterface;
    }

    public void setNetworkInterface(String networkInterface) {
        this.networkInterface = networkInterface;
    }

    public String getGateway() {
        return gateway;
    }

    public void setGateway(String gateway) {
        this.gateway = gateway;
    }

    public String getCidr() {
        return cidr;
    }

    public void setCidr(String cidr) {
        this.cidr = cidr;
    }

    public String getSubnetMask() {
        return subnetMask;
    }

    public void setSubnetMask(String subnetMask) {
        this.subnetMask = subnetMask;
    }

    public String getDnsServers() {
        return dnsServers;
    }

    public void setDnsServers(String dnsServers) {
        this.dnsServers = dnsServers;
    }

    public String getConnectionType() {
        return connectionType;
    }

    public void setConnectionType(String connectionType) {
        this.connectionType = connectionType;
    }

    public String getSsid() {
        return ssid;
    }

    public void setSsid(String ssid) {
        this.ssid = ssid;
    }

    public String getBssid() {
        return bssid;
    }

    public void setBssid(String bssid) {
        this.bssid = bssid;
    }

    public Boolean getProxyEnabled() {
        return proxyEnabled;
    }

    public void setProxyEnabled(Boolean proxyEnabled) {
        this.proxyEnabled = proxyEnabled;
    }

    public String getProxyHost() {
        return proxyHost;
    }

    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }

    public Integer getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(Integer proxyPort) {
        this.proxyPort = proxyPort;
    }

    public Boolean getVpnEnabled() {
        return vpnEnabled;
    }

    public void setVpnEnabled(Boolean vpnEnabled) {
        this.vpnEnabled = vpnEnabled;
    }

    public String getVpnEndpoint() {
        return vpnEndpoint;
    }

    public void setVpnEndpoint(String vpnEndpoint) {
        this.vpnEndpoint = vpnEndpoint;
    }

    public List<PortConfig> getPorts() {
        return ports;
    }

    public void setPorts(List<PortConfig> ports) {
        this.ports = ports;
    }
}
