package com.manager.Zombie_Keeper.model.entity.c2Server;

import com.manager.Zombie_Keeper.model.entity.agent.Agent;
import jakarta.persistence.*;

@Entity
@Table(name = "tb_server_location")
public class ServerLocation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // fk do server
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "c_2_server_id", nullable = false)
    private C2Server server;

    @Column(nullable = false)
    private Double lat;

    @Column(nullable = false)
    private Double lng;

    @Column
    private String city;

    @Column
    private String country;

    @Column
    private String region;


    public ServerLocation() {}

    public ServerLocation(Long id, C2Server server, Double lat, Double lng, String city, String country, String region) {
        this.id = id;
        this.server = server;
        this.lat = lat;
        this.lng = lng;
        this.city = city;
        this.country = country;
        this.region = region;
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

    public Double getLat() {
        return lat;
    }

    public void setLat(Double lat) {
        this.lat = lat;
    }

    public Double getLng() {
        return lng;
    }

    public void setLng(Double lng) {
        this.lng = lng;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }
}
