package com.manager.Zombie_Keeper.model.entity.localNetwork;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "tb_node_ports")
public class Port {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "node_id")
    @JsonIgnore
    private NetworkNode node;

    @JsonProperty("number")
    private int number;

    @JsonProperty("proto")
    private String protocol;

    @JsonProperty("service")
    private String service;

    @JsonProperty("banner")
    @Column(columnDefinition = "TEXT")
    private String banner;

    public Port(int number, String protocol, String service, String banner) {
        this.number = number;
        this.protocol = protocol;
        this.service = service;
        this.banner = banner;
    }

    public Port() {
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public NetworkNode getNode() {
        return this.node;
    }

    public void setNode(NetworkNode node) {
        this.node = node;
    }

    public int getNumber() {
        return this.number;
    }

    public void setNumber(int number) {
        this.number = number;
    }

    public String getProtocol() {
        return this.protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getService() {
        return this.service;
    }

    public void setService(String service) {
        this.service = service;
    }

    public String getBanner() {
        return this.banner;
    }

    public void setBanner(String banner) {
        this.banner = banner;
    }
}