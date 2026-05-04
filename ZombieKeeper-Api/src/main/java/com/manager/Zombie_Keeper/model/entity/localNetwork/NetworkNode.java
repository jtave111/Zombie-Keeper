package com.manager.Zombie_Keeper.model.entity.localNetwork;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "network_node")
public class NetworkNode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    

    @JsonProperty("ipv4")
    @Column(name = "ipv4", length = 15)
    private String ipv4;

    @JsonProperty("ipv6")
    @Column(name = "ipv6", length = 39)
    private String ipv6;

    @JsonProperty("mac")
    @Column(name = "mac_address", length = 17)
    private String macAddress;

    @JsonProperty("hostname")
    private String hostname;

    @JsonProperty("os")
    private String os;

    @JsonProperty("architecture")
    @Column(length = 20)
    private String architecture;

    @JsonProperty("status")
    @Column(length = 20)
    private String status;

    @JsonProperty("first_seen")
    @Column(name = "first_seen")
    private LocalDateTime firstSeen;

    @JsonProperty("last_seen")
    @Column(name = "last_seen")
    private LocalDateTime lastSeen;

    @JsonProperty("vendor")
    private String vendor;

    @JsonProperty("is_trusted")
    @Column(name = "is_trusted")
    private boolean isTrusted;

    @JsonProperty("vulnerability_score")
    @Column(name = "vulnerability_score")
    private int vulnerabilityScore; 

    @JsonProperty("is_agent")
    @Column(name = "is_agent")
    private boolean isAgent;

    
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

   
    public void addPort(Port port){
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

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getIpv4() { return ipv4; }
    public void setIpv4(String ipv4) { this.ipv4 = ipv4; }

    public String getIpv6() { return ipv6; }
    public void setIpv6(String ipv6) { this.ipv6 = ipv6; }

    public String getMacAddress() { return macAddress; }
    public void setMacAddress(String macAddress) { this.macAddress = macAddress; }

    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }

    public String getOs() { return os; }
    public void setOs(String os) { this.os = os; }

    public String getArchitecture() { return architecture; }
    public void setArchitecture(String architecture) { this.architecture = architecture; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public LocalDateTime getFirstSeen() { return firstSeen; }
    public void setFirstSeen(LocalDateTime firstSeen) { this.firstSeen = firstSeen; }

    public LocalDateTime getLastSeen() { return lastSeen; }
    public void setLastSeen(LocalDateTime lastSeen) { this.lastSeen = lastSeen; }

    public String getVendor() { return vendor; }
    public void setVendor(String vendor) { this.vendor = vendor; }

    public boolean isTrusted() { return isTrusted; }
    public void setTrusted(boolean isTrusted) { this.isTrusted = isTrusted; }

    public int getVulnerabilityScore() { return vulnerabilityScore; }
    public void setVulnerabilityScore(int vulnerabilityScore) { this.vulnerabilityScore = vulnerabilityScore; }

    public boolean isAgent() { return isAgent; }
    public void setAgent(boolean isAgent) { this.isAgent = isAgent; }

    public List<Port> getOpenPorts() { return openPorts; }
    public void setOpenPorts(List<Port> openPorts) { this.openPorts = openPorts; }

    public List<Vulnerability> getVulnerabilities() { return vulnerabilities; }
    public void setVulnerabilities(List<Vulnerability> vulnerabilities) { this.vulnerabilities = vulnerabilities; }

    public NetworkSession getNetwork() { return network; }
    public void setNetwork(NetworkSession network) { this.network = network; }
}