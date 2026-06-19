package com.manager.Zombie_Keeper.model.entity.c2Server;

import com.manager.Zombie_Keeper.model.entity.agent.Agent;
import com.manager.Zombie_Keeper.model.enums.server.StatusServer;
import jakarta.persistence.*;

import java.util.Date;
import java.util.List;

@Entity
@Table(name = "tb_c2_server")
public class C2Server {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String framework;
    private Date uptime;
    private String publicUrl;
    private Date lastSeen;



    @OneToMany(mappedBy = "server")
    private List<Agent> agents;
    private int agentsCount;

    @OneToMany(mappedBy = "server")
    private List<NetworkConfig> networkConfigs;

    private StatusServer status = StatusServer.ONLINE;

    @ElementCollection
    @CollectionTable(name = "c2_listeners", joinColumns = @JoinColumn(name = "server_id"))
    @Column(name = "listener")
    private List<String> listeners;

    private int threads;
    private String memory;
    private String CpuLoad;
    private String DiskFree;


    @OneToMany(mappedBy = "server")
    private List<ServerLocation> locations;


    private String version;

    @OneToMany(mappedBy = "server")
    private List<DatabaseConfig> databaseConfigs;

    @OneToMany(mappedBy = "server")
    private List<AutomationConfig> automationConfigs;

    @OneToOne(mappedBy = "server")
    private WebConfig webConfig;

    @OneToOne(mappedBy = "server")
    private SecurityConfig securityConfig;

    public C2Server() {}

    public C2Server(Long id, String framework, Date uptime, String publicUrl, Date lastSeen, List<Agent> agents,
                    int agentsCount, List<NetworkConfig> networkConfigs, StatusServer status, List<String> listeners,
                    int threads, String memory, String cpuLoad, String diskFree, List<ServerLocation> locations,
                    String version, List<DatabaseConfig> databaseConfigs, List<AutomationConfig> automationConfigs,
                    WebConfig webConfig, SecurityConfig securityConfig) {
        this.id = id;
        this.framework = framework;
        this.uptime = uptime;
        this.publicUrl = publicUrl;
        this.lastSeen = lastSeen;
        this.agents = agents;
        this.agentsCount = agentsCount;
        this.networkConfigs = networkConfigs;
        this.status = status;
        this.listeners = listeners;
        this.threads = threads;
        this.memory = memory;
        CpuLoad = cpuLoad;
        DiskFree = diskFree;
        this.locations = locations;
        this.version = version;
        this.databaseConfigs = databaseConfigs;
        this.automationConfigs = automationConfigs;
        this.webConfig = webConfig;
        this.securityConfig = securityConfig;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getFramework() {
        return framework;
    }

    public void setFramework(String framework) {
        this.framework = framework;
    }

    public Date getUptime() {
        return uptime;
    }

    public void setUptime(Date uptime) {
        this.uptime = uptime;
    }

    public String getPublicUrl() {
        return publicUrl;
    }

    public void setPublicUrl(String publicUrl) {
        this.publicUrl = publicUrl;
    }

    public Date getLastSeen() {
        return lastSeen;
    }

    public void setLastSeen(Date lastSeen) {
        this.lastSeen = lastSeen;
    }

    public List<Agent> getAgents() {
        return agents;
    }

    public void setAgents(List<Agent> agents) {
        this.agents = agents;
    }

    public int getAgentsCount() {
        return agentsCount;
    }

    public void setAgentsCount(int agentsCount) {
        this.agentsCount = agentsCount;
    }

    public List<NetworkConfig> getNetworkConfigs() {
        return networkConfigs;
    }

    public void setNetworkConfigs(List<NetworkConfig> networkConfigs) {
        this.networkConfigs = networkConfigs;
    }

    public StatusServer getStatus() {
        return status;
    }

    public void setStatus(StatusServer status) {
        this.status = status;
    }

    public List<String> getListeners() {
        return listeners;
    }

    public void setListeners(List<String> listeners) {
        this.listeners = listeners;
    }

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = threads;
    }

    public String getMemory() {
        return memory;
    }

    public void setMemory(String memory) {
        this.memory = memory;
    }

    public String getCpuLoad() {
        return CpuLoad;
    }

    public void setCpuLoad(String cpuLoad) {
        CpuLoad = cpuLoad;
    }

    public String getDiskFree() {
        return DiskFree;
    }

    public void setDiskFree(String diskFree) {
        DiskFree = diskFree;
    }

    public List<ServerLocation> getLocations() {
        return locations;
    }

    public void setLocations(List<ServerLocation> locations) {
        this.locations = locations;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public List<DatabaseConfig> getDatabaseConfigs() {
        return databaseConfigs;
    }

    public void setDatabaseConfigs(List<DatabaseConfig> databaseConfigs) {
        this.databaseConfigs = databaseConfigs;
    }

    public List<AutomationConfig> getAutomationConfigs() {
        return automationConfigs;
    }

    public void setAutomationConfigs(List<AutomationConfig> automationConfigs) {
        this.automationConfigs = automationConfigs;
    }

    public WebConfig getWebConfig() {
        return webConfig;
    }

    public void setWebConfig(WebConfig webConfig) {
        this.webConfig = webConfig;
    }

    public SecurityConfig getSecurityConfig() {
        return securityConfig;
    }

    public void setSecurityConfig(SecurityConfig securityConfig) {
        this.securityConfig = securityConfig;
    }
}
