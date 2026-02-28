package com.manager.Zombie_Keeper.model.entity.localNetwork;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;

@Entity
@Table(name = "network_session")
public class NetworkSession {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    private UUID id;

    // MAC gateway or SSID + BSSID
    @JsonProperty("network_identifier")
    @Column(name = "network_identifier", nullable = false, length = 700)
    private String networkIdentifier;

    // Ex: "Starbucks WiFi", "CORP-DOMAIN.local"
    @JsonProperty("network_name")
    @Column(name = "network_name")
    private String networkName;

    // Ex: "eth0", "wlan0", "ens33"
    @JsonProperty("network_interface")
    @Column(name = "network_interface")
    private String networkInterface;

    // Ex: "WIFI", "ETHERNET", "VPN"
    @JsonProperty("network_type")
    @Column(name = "network_type", length = 50)
    private String networkType;

    @JsonProperty("gateway_ip")
    @Column(name = "gateway_ip")
    private String gatewayIp;

    @JsonProperty("subnet_mask")
    @Column(name = "subnet_mask")
    private String subnetMask;

    @JsonProperty("cidr")
    private String cidr;

    @JsonProperty("first_seen")
    @Column(name = "first_seen")
    private LocalDateTime firstSeen; 

    @JsonProperty("last_seen")
    @Column(name = "last_seen")
    private LocalDateTime lastSeen;

    @OneToMany(mappedBy = "network", cascade = CascadeType.ALL, orphanRemoval = true)  
    @JsonProperty("nodes") 
    private List<NetworkNode> devices = new ArrayList<>();

    // =========================================
    // HOOKS (Gatilhos do Hibernate)
    // =========================================

    @PrePersist
    public void onPrePersist() {
        if (this.firstSeen == null) {
            this.firstSeen = LocalDateTime.now();
        }
        this.lastSeen = LocalDateTime.now();
    }

    // Automatiza o update do último visto sempre que a sessão for alterada
    @PreUpdate
    public void onPreUpdate() {
        this.lastSeen = LocalDateTime.now();
    }

    // =========================================
    // MÉTODOS AUXILIARES (Boa prática)
    // =========================================

    public void addDevice(NetworkNode node) {
        devices.add(node);
        node.setNetwork(this);
    }

    public void removeDevice(NetworkNode node) {
        devices.remove(node);
        node.setNetwork(null);
    }

    // =========================================
    // GETTERS E SETTERS
    // =========================================

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getNetworkIdentifier() { return networkIdentifier; }
    public void setNetworkIdentifier(String networkIdentifier) { this.networkIdentifier = networkIdentifier; }

    public String getNetworkName() { return networkName; }
    public void setNetworkName(String networkName) { this.networkName = networkName; }

    public String getNetworkInterface() { return networkInterface; }
    public void setNetworkInterface(String networkInterface) { this.networkInterface = networkInterface; }

    public String getNetworkType() { return networkType; }
    public void setNetworkType(String networkType) { this.networkType = networkType; }

    public String getGatewayIp() { return gatewayIp; }
    public void setGatewayIp(String gatewayIp) { this.gatewayIp = gatewayIp; }

    public String getSubnetMask() { return subnetMask; }
    public void setSubnetMask(String subnetMask) { this.subnetMask = subnetMask; }

    public String getCidr() { return cidr; }
    public void setCidr(String cidr) { this.cidr = cidr; }

    public LocalDateTime getFirstSeen() { return firstSeen; }
    public void setFirstSeen(LocalDateTime firstSeen) { this.firstSeen = firstSeen; }

    public LocalDateTime getLastSeen() { return lastSeen; }
    public void setLastSeen(LocalDateTime lastSeen) { this.lastSeen = lastSeen; }

    public List<NetworkNode> getDevices() { return devices; }
    public void setDevices(List<NetworkNode> devices) { this.devices = devices; }
}