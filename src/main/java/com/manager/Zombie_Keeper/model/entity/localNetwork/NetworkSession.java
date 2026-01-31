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

@Entity
public class NetworkSession {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    private UUID id;
    //Mac gateway or SSID + BSSID
    @Column(nullable = false, length = 700)
    private String networkIdentifier;

    //TODO criar
   // private String networkInterface;

    private String gatewayIp;
    private String subnetMask;
    private String cidr;

    private LocalDateTime firstSeen; 
    private LocalDateTime lastSeen;

    @OneToMany(mappedBy = "network", cascade = CascadeType.ALL, orphanRemoval = true)  
    @JsonProperty("nodes") 
    private List<NetworkNode> devices = new ArrayList<>();


    @PrePersist
    public void prePersist() {
        if (this.firstSeen == null) {
            this.firstSeen = LocalDateTime.now();
        }
        this.lastSeen = LocalDateTime.now();
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getNetworkIdentifier() {
        return networkIdentifier;
    }

    public void setNetworkIdentifier(String networkIdentifier) {
        this.networkIdentifier = networkIdentifier;
    }

    public String getGatewayIp() {
        return gatewayIp;
    }

    public void setGatewayIp(String gatewayIp) {
        this.gatewayIp = gatewayIp;
    }

    public String getSubnetMask() {
        return subnetMask;
    }

    public void setSubnetMask(String subnetMask) { 
        this.subnetMask = subnetMask;
    }

    public String getCidr() {
        return cidr;
    }

    public void setCidr(String cidr) {
        this.cidr = cidr;
    }

    public LocalDateTime getFirstSeen() { 
        return firstSeen;
    }

    public void setFirstSeen(LocalDateTime firstSeen) { 
        this.firstSeen = firstSeen;
    }

    public LocalDateTime getLastSeen() {
        return lastSeen;
    }

    public void setLastSeen(LocalDateTime lastSeen) {
        this.lastSeen = lastSeen;
    }

    public List<NetworkNode> getDevices() {
        return devices;
    }

    public void setDevices(List<NetworkNode> devices) {
        this.devices = devices;
    }

}
