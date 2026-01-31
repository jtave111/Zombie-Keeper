package com.manager.Zombie_Keeper.model.entity.localNetwork;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "network_node")
public class NetworkNode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @JsonProperty("ip")
    @Column(name = "ip_address")
    private String ipAddress;

    @JsonProperty("mac")
    @Column(name = "mac_address")
    private String macAddress;

    @JsonProperty("hostname")
    @Column(nullable = true)
    private String hostname;

    @JsonProperty("vendor")
    @Column(nullable = true)
    private String vendor;

    @JsonProperty("os")
    @Column(nullable = true)
    private String os;

    @JsonProperty("is_trusted")
    @Column(nullable = true)
    private boolean isTrusted;

    @JsonProperty("vulnerability_score")
    @Column(nullable = true)
    private int vunerabilityScore;
    
    @OneToMany(mappedBy = "node", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonProperty("ports")
    private List<Port> openPorts = new ArrayList<>();

    @OneToMany(mappedBy = "node", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<Vulnerability> vulnerabilities = new ArrayList<>();

    @ManyToOne
    @JoinColumn(name = "network_id")
    @JsonIgnore
    private NetworkSession network;

    public void addPort(Port port ){
        openPorts.add(port);
        port.setNode(this);
    }

    public void deletePort(Port port){
        openPorts.remove(port);
        port.setNode(null);
    }
    
    public void addVulnerability(Vulnerability vuln) {
        vulnerabilities.add(vuln);
        vuln.setNode(this);
    }

    public void removeVulnerability(Vulnerability vuln) {
        vulnerabilities.remove(vuln);
        vuln.setNode(null);
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }
    
    public String getOs(){
        return this.os;
    }

    public void setOs(String os ){
        this.os = os;
    }

    public List<Port> getOpenPorts() {
        return openPorts;
    }

    public void setOpenPorts(List<Port> openPorts) {
        this.openPorts = openPorts;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getVendor() {
        return vendor;
    }

    public void setVendor(String vendor) {
        this.vendor = vendor;
    }

    public boolean isTrusted() {
        return isTrusted;
    }

    public void setTrusted(boolean isTrusted) {
        this.isTrusted = isTrusted;
    }

    public int getVunerabilityScore() {
        return vunerabilityScore;
    }

    public void setVunerabilityScore(int vunerabilityScore) {
        this.vunerabilityScore = vunerabilityScore;
    }

    public List<Vulnerability> getVulnerabilitys(){
        return this.vulnerabilities;
    }

    public void setVulnerability(List<Vulnerability> vulnerabilities){
        this.vulnerabilities = vulnerabilities;

    }

    public NetworkSession getNetwork() {
        return network;
    }

    public void setNetwork(NetworkSession network) {
        this.network = network;
    }
}
