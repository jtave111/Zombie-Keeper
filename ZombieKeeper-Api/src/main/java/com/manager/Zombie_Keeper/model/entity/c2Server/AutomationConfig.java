package com.manager.Zombie_Keeper.model.entity.c2Server;

import jakarta.persistence.*;

@Entity
@Table(name = "tb_automation_config")
public class AutomationConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "server_id")
    private C2Server server;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "port_id")
    private PortConfig port;

    private Boolean enabled = true;

    @Column(length = 256)
    private String pythonPath = "/usr/bin/python3";

    @Column(length = 512)
    private String scriptsDir;

    @Column(length = 512)
    private String apiUrl;

    private Integer pollingIntervalMs = 60000;

    private Integer maxRetries = 3;

    private Integer retryDelayMs = 5000;

    @Column(length = 512)
    private String webhookUrl;

    private Boolean autoRecon = false;

    private Long reconIntervalMs = 3600000L; // 1h

    @Column(length = 10)
    private String logLevel = "INFO"; // DEBUG, INFO, WARN, ERROR

    public AutomationConfig() {}

    public AutomationConfig(Long id, C2Server server, PortConfig port, Boolean enabled,
                            String pythonPath, String scriptsDir, String apiUrl, Integer pollingIntervalMs,
                            Integer maxRetries, Integer retryDelayMs, String webhookUrl, Boolean autoRecon,
                            Long reconIntervalMs, String logLevel) {
        this.id = id;
        this.server = server;
        this.port = port;
        this.enabled = enabled;
        this.pythonPath = pythonPath;
        this.scriptsDir = scriptsDir;
        this.apiUrl = apiUrl;
        this.pollingIntervalMs = pollingIntervalMs;
        this.maxRetries = maxRetries;
        this.retryDelayMs = retryDelayMs;
        this.webhookUrl = webhookUrl;
        this.autoRecon = autoRecon;
        this.reconIntervalMs = reconIntervalMs;
        this.logLevel = logLevel;
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

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public String getPythonPath() {
        return pythonPath;
    }

    public void setPythonPath(String pythonPath) {
        this.pythonPath = pythonPath;
    }

    public String getScriptsDir() {
        return scriptsDir;
    }

    public void setScriptsDir(String scriptsDir) {
        this.scriptsDir = scriptsDir;
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public void setApiUrl(String apiUrl) {
        this.apiUrl = apiUrl;
    }

    public Integer getPollingIntervalMs() {
        return pollingIntervalMs;
    }

    public void setPollingIntervalMs(Integer pollingIntervalMs) {
        this.pollingIntervalMs = pollingIntervalMs;
    }

    public Integer getMaxRetries() {
        return maxRetries;
    }

    public void setMaxRetries(Integer maxRetries) {
        this.maxRetries = maxRetries;
    }

    public Integer getRetryDelayMs() {
        return retryDelayMs;
    }

    public void setRetryDelayMs(Integer retryDelayMs) {
        this.retryDelayMs = retryDelayMs;
    }

    public String getWebhookUrl() {
        return webhookUrl;
    }

    public void setWebhookUrl(String webhookUrl) {
        this.webhookUrl = webhookUrl;
    }

    public Boolean getAutoRecon() {
        return autoRecon;
    }

    public void setAutoRecon(Boolean autoRecon) {
        this.autoRecon = autoRecon;
    }

    public Long getReconIntervalMs() {
        return reconIntervalMs;
    }

    public void setReconIntervalMs(Long reconIntervalMs) {
        this.reconIntervalMs = reconIntervalMs;
    }

    public String getLogLevel() {
        return logLevel;
    }

    public void setLogLevel(String logLevel) {
        this.logLevel = logLevel;
    }
}
