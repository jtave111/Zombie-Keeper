// com/manager/Zombie_Keeper/model/entity/agent/AgentLocation.java
package com.manager.Zombie_Keeper.model.entity.agent;

import com.manager.Zombie_Keeper.model.enums.agent.LocationSource;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "agent_locations")
public class AgentLocation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // FK para o agente
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "agent_id", nullable = false)
    private Agent agent;

    // Coordenadas
    @Column(nullable = false)
    private Double lat;

    @Column(nullable = false)
    private Double lng;

    // Dados geográficos
    @Column
    private String city;

    @Column
    private String country;

    @Column
    private String region;

    // Origem da localização
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private LocationSource source; // GPS | WIFI | IP | UNKNOWN

    // Precisão em metros (GPS e WiFi retornam isso, IP deixa null)
    @Column
    private Double accuracyMeters;

    @Column(nullable = false)
    private LocalDateTime capturedAt;



    public AgentLocation() {}

    public AgentLocation(Agent agent, Double lat, Double lng,
                         String city, String country, String region,
                         LocationSource source, Double accuracyMeters) {
        this.agent          = agent;
        this.lat            = lat;
        this.lng            = lng;
        this.city           = city;
        this.country        = country;
        this.region         = region;
        this.source         = source;
        this.accuracyMeters = accuracyMeters;
        this.capturedAt     = LocalDateTime.now();
    }

    public Long getId()                  { return id; }
    public Agent getAgent()              { return agent; }
    public Double getLat()               { return lat; }
    public Double getLng()               { return lng; }
    public String getCity()              { return city; }
    public String getCountry()           { return country; }
    public String getRegion()            { return region; }
    public LocationSource getSource()    { return source; }
    public Double getAccuracyMeters()    { return accuracyMeters; }
    public LocalDateTime getCapturedAt() { return capturedAt; }

    public void setAgent(Agent agent)                   { this.agent          = agent; }
    public void setLat(Double lat)                      { this.lat            = lat; }
    public void setLng(Double lng)                      { this.lng            = lng; }
    public void setCity(String city)                    { this.city           = city; }
    public void setCountry(String country)              { this.country        = country; }
    public void setRegion(String region)                { this.region         = region; }
    public void setSource(LocationSource source)        { this.source         = source; }
    public void setAccuracyMeters(Double accuracyMeters){ this.accuracyMeters = accuracyMeters; }
    public void setCapturedAt(LocalDateTime capturedAt) { this.capturedAt     = capturedAt; }
}