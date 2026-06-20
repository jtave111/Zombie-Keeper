package com.manager.Zombie_Keeper.model.entity.c2Server;

import jakarta.persistence.*;

@Entity
@Table(name = "tb_web_config")
public class WebConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "c_2_server_id")
    private C2Server server;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "port_id")
    private PortConfig port;

    private String url;

    private Boolean enabled = true;

    private Boolean sslEnabled = false;

    private Boolean maintenanceMode = false;

    // Sessões de operador
    private Long sessionTimeoutMs = 86400000L; // 24h

    private Integer maxConcurrentSessions = 10;

    @Column(length = 512)
    private String allowedIps; // comma-separated whitelist, null = sem restrição

    // Dashboard
    private Boolean wsEnabled = true; // WebSocket para shell e feed em tempo real

    private Integer agentRefreshIntervalMs = 30000; // polling de agents

    @Column(length = 10)
    private String theme = "DARK";

    public WebConfig() {}

    public WebConfig(Long id, C2Server server, PortConfig port, String url, Boolean enabled, Boolean sslEnabled,
                     Boolean maintenanceMode, Long sessionTimeoutMs, Integer maxConcurrentSessions, String allowedIps,
                     Boolean wsEnabled, Integer agentRefreshIntervalMs, String theme) {
        this.id = id;
        this.server = server;
        this.port = port;
        this.url = url;
        this.enabled = enabled;
        this.sslEnabled = sslEnabled;
        this.maintenanceMode = maintenanceMode;
        this.sessionTimeoutMs = sessionTimeoutMs;
        this.maxConcurrentSessions = maxConcurrentSessions;
        this.allowedIps = allowedIps;
        this.wsEnabled = wsEnabled;
        this.agentRefreshIntervalMs = agentRefreshIntervalMs;
        this.theme = theme;
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

    public PortConfig getPort() {
        return port;
    }

    public void setPort(PortConfig port) {
        this.port = port;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Boolean getSslEnabled() {
        return sslEnabled;
    }

    public void setSslEnabled(Boolean sslEnabled) {
        this.sslEnabled = sslEnabled;
    }

    public Boolean getMaintenanceMode() {
        return maintenanceMode;
    }

    public void setMaintenanceMode(Boolean maintenanceMode) {
        this.maintenanceMode = maintenanceMode;
    }

    public Long getSessionTimeoutMs() {
        return sessionTimeoutMs;
    }

    public void setSessionTimeoutMs(Long sessionTimeoutMs) {
        this.sessionTimeoutMs = sessionTimeoutMs;
    }

    public Integer getMaxConcurrentSessions() {
        return maxConcurrentSessions;
    }

    public void setMaxConcurrentSessions(Integer maxConcurrentSessions) {
        this.maxConcurrentSessions = maxConcurrentSessions;
    }

    public String getAllowedIps() {
        return allowedIps;
    }

    public void setAllowedIps(String allowedIps) {
        this.allowedIps = allowedIps;
    }

    public Boolean getWsEnabled() {
        return wsEnabled;
    }

    public void setWsEnabled(Boolean wsEnabled) {
        this.wsEnabled = wsEnabled;
    }

    public Integer getAgentRefreshIntervalMs() {
        return agentRefreshIntervalMs;
    }

    public void setAgentRefreshIntervalMs(Integer agentRefreshIntervalMs) {
        this.agentRefreshIntervalMs = agentRefreshIntervalMs;
    }

    public String getTheme() {
        return theme;
    }

    public void setTheme(String theme) {
        this.theme = theme;
    }

}
