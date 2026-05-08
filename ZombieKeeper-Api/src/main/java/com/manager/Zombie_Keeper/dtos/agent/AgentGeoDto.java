package com.manager.Zombie_Keeper.dtos.agent;

public class AgentGeoDto {

    private String id;
    private String ip;
    private String hostname;
    private Double lat;
    private Double lng;
    private String country;
    private String city;
    private String status;
    private String priv;

    public AgentGeoDto() {
    }

    public AgentGeoDto(String id, String ip, String hostname, Double lat, Double lng, String country, String city, String status, String priv) {
        this.id = id;
        this.ip = ip;
        this.hostname = hostname;
        this.lat = lat;
        this.lng = lng;
        this.country = country;
        this.city = city;
        this.status = status;
        this.priv = priv;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }

    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }

    public Double getLat() { return lat; }
    public void setLat(Double lat) { this.lat = lat; }

    public Double getLng() { return lng; }
    public void setLng(Double lng) { this.lng = lng; }

    public String getCountry() { return country; }
    public void setCountry(String country) { this.country = country; }

    public String getCity() { return city; }
    public void setCity(String city) { this.city = city; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getPriv() { return priv; }
    public void setPriv(String priv) { this.priv = priv; }
}
