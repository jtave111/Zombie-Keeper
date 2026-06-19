package com.manager.Zombie_Keeper.model.entity.agent;

import com.manager.Zombie_Keeper.model.entity.c2Server.C2Server;
import com.manager.Zombie_Keeper.model.enums.agent.StatusAgent;
import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import com.manager.Zombie_Keeper.model.enums.agent.Flags;
import com.manager.Zombie_Keeper.model.enums.agent.Tags;

@Entity
@Table(name = "tb_agent")
public class Agent {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(updatable = false, nullable = false)
    private UUID id;

    @Column(unique = true, nullable = false, updatable = false)
    private Long publicId;

    private String hostname;
    private String os;
    
    @Column(length = 20)
    private String architecture; // e.g., "x86_64", "arm64"
    
    @Column(length = 100)
    private String loggedUser; // e.g., "NT AUTHORITY\SYSTEM" or "root"
    
    @Column(nullable = false)
    private Boolean isElevated = false; // True if Admin/Root

    @Column(length = 15)
    private String ipv4;

    @Column(length = 39)
    private String ipv6;

    @Column(length = 17)
    private String macAddress;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private StatusAgent status = StatusAgent.ONLINE;
    
    private Integer sleepTime = 0; // Beacon interval in seconds (0 = interactive)

    @Column(updatable = false)
    private LocalDateTime firstSeen; // When the agent first registered

    private LocalDateTime lastSeen; // Last time it checked in



    @OneToMany(mappedBy = "agent", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Loot> loots = new ArrayList<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "agent_flags", joinColumns = @JoinColumn(name = "agent_id"))
    @Enumerated(EnumType.STRING)
    private Set<Flags> flags = new HashSet<>();
    
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "agent_tags", joinColumns = @JoinColumn(name = "agent_id"))
    @Enumerated(EnumType.STRING)
    private Set<Tags> tags = new HashSet<>();


    @ManyToOne
    @JoinColumn(name = "c_2_server_id")
    private C2Server server;

    @OneToMany(
            mappedBy      = "agent",
            cascade       = CascadeType.ALL,   // salvar/deletar agent cascateia locations
            orphanRemoval = true,              // remove locations órfãs automaticamente
            fetch         = FetchType.LAZY     // não carrega locations a cada getAgent()
    )
    private List<AgentLocation> locations = new ArrayList<>();

    public C2Server getC2Server() {
        return server;
    }

    public void setC2Server(C2Server server) {
        this.server = server;
    }

    public Agent() {

    }

    public Agent(Integer sleepTime, LocalDateTime firstSeen, LocalDateTime lastSeen,
                 String status, String macAddress, String ipv6, Boolean isElevated,
                 String ipv4, String loggedUser, String architecture, String hostname, String os, Long publicId) {

        this.sleepTime = sleepTime;
        this.firstSeen = firstSeen;
        this.lastSeen = lastSeen;
        this.status = StatusAgent.valueOf(status);
        this.macAddress = macAddress;
        this.ipv6 = ipv6;
        this.isElevated = isElevated;
        this.ipv4 = ipv4;
        this.loggedUser = loggedUser;
        this.architecture = architecture;
        this.hostname = hostname;
        this.os = os;
        this.publicId = publicId;
    }

    @PrePersist
    public void onCreate() {
        if (this.publicId == null) {
            this.publicId = ThreadLocalRandom.current().nextLong(10000000, 99999999);
        }
        if (this.firstSeen == null) {
            this.firstSeen = LocalDateTime.now();
        }
        if (this.lastSeen == null) {           
            this.lastSeen = LocalDateTime.now();
        }
    }


    public List<AgentLocation> getLocations() { return locations; }

    public void setLocations(List<AgentLocation> locations) { this.locations = locations; }


    public void addLocation(AgentLocation location) {
        locations.add(location);
        location.setAgent(this);
    }

    public void removeLocation(AgentLocation location) {
        locations.remove(location);
        location.setAgent(null);
    }

    @PreUpdate
    public void onUpdate() {
        this.lastSeen = LocalDateTime.now();
    }

  
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public Long getPublicId() { return publicId; }
    public void setPublicId(Long publicId) { this.publicId = publicId; }

    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }

    public String getOs() { return os; }
    public void setOs(String os) { this.os = os; }

    public String getArchitecture() { return architecture; }
    public void setArchitecture(String architecture) { this.architecture = architecture; }

    public String getLoggedUser() { return loggedUser; }
    public void setLoggedUser(String loggedUser) { this.loggedUser = loggedUser; }

    public Boolean getIsElevated() { return isElevated; }
    public void setIsElevated(Boolean isElevated) { this.isElevated = isElevated; }

    public String getIpv4() { return ipv4; }
    public void setIpv4(String ipv4) { this.ipv4 = ipv4; }
    
    public String getIpv6() { return ipv6; }
    public void setIpv6(String ipv6) { this.ipv6 = ipv6; }

    public String getMacAddress() { return macAddress; }
    public void setMacAddress(String macAddress) { this.macAddress = macAddress; }

    public StatusAgent getStatus() { return status; }
    public void setStatus(StatusAgent status) { this.status = status; }

    public Integer getSleepTime() { return sleepTime; }
    public void setSleepTime(Integer sleepTime) { this.sleepTime = sleepTime; }

    public LocalDateTime getFirstSeen() { return firstSeen; }
    public void setFirstSeen(LocalDateTime firstSeen) { this.firstSeen = firstSeen; }

    public LocalDateTime getLastSeen() { return lastSeen; }
    public void setLastSeen(LocalDateTime lastSeen) { this.lastSeen = lastSeen; }

    public List<Loot> getLoots() { return loots; }
    public void setLoots(List<Loot> loots) { this.loots = loots; }

    public Set<Tags> getTags() { return tags; }
    public void setTags(Set<Tags> tags) { this.tags = tags; }

    public Set<Flags> getFlags() { return flags; }
    public void setFlags(Set<Flags> flags) { this.flags = flags; }
}