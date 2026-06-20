package com.manager.Zombie_Keeper.model.entity.c2Server;

import jakarta.persistence.*;

@Entity
@Table(name = "tb_api_config")
public class ApiConfig {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "port_id")
    private PortConfig port;


    private String url;

    @Column(length = 10)
    private String apiVersion = "v1";

    private Boolean sslEnabled = false;

    private Boolean enabled = true;

    // CORS
    @Column(length = 512)
    private String corsAllowedOrigins;

    @Column(length = 256)
    private String corsAllowedMethods = "GET,POST,PUT,DELETE,OPTIONS";

    private Boolean corsAllowCredentials = true;

    // Limites
    private Integer rateLimitPerMinute;

    private Integer requestTimeoutMs = 30000;

    private Integer maxConnections = 100;


    public ApiConfig() {}

    public ApiConfig(Long id, PortConfig port, String url, String apiVersion, Boolean sslEnabled, Boolean enabled,
                     String corsAllowedOrigins, String corsAllowedMethods, Boolean corsAllowCredentials,
                     Integer rateLimitPerMinute, Integer requestTimeoutMs, Integer maxConnections) {
        this.id = id;
        this.port = port;
        this.url = url;
        this.apiVersion = apiVersion;
        this.sslEnabled = sslEnabled;
        this.enabled = enabled;
        this.corsAllowedOrigins = corsAllowedOrigins;
        this.corsAllowedMethods = corsAllowedMethods;
        this.corsAllowCredentials = corsAllowCredentials;
        this.rateLimitPerMinute = rateLimitPerMinute;
        this.requestTimeoutMs = requestTimeoutMs;
        this.maxConnections = maxConnections;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
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

    public String getApiVersion() {
        return apiVersion;
    }

    public void setApiVersion(String apiVersion) {
        this.apiVersion = apiVersion;
    }

    public Boolean getSslEnabled() {
        return sslEnabled;
    }

    public void setSslEnabled(Boolean sslEnabled) {
        this.sslEnabled = sslEnabled;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public String getCorsAllowedOrigins() {
        return corsAllowedOrigins;
    }

    public void setCorsAllowedOrigins(String corsAllowedOrigins) {
        this.corsAllowedOrigins = corsAllowedOrigins;
    }

    public String getCorsAllowedMethods() {
        return corsAllowedMethods;
    }

    public void setCorsAllowedMethods(String corsAllowedMethods) {
        this.corsAllowedMethods = corsAllowedMethods;
    }

    public Boolean getCorsAllowCredentials() {
        return corsAllowCredentials;
    }

    public void setCorsAllowCredentials(Boolean corsAllowCredentials) {
        this.corsAllowCredentials = corsAllowCredentials;
    }

    public Integer getRateLimitPerMinute() {
        return rateLimitPerMinute;
    }

    public void setRateLimitPerMinute(Integer rateLimitPerMinute) {
        this.rateLimitPerMinute = rateLimitPerMinute;
    }

    public Integer getRequestTimeoutMs() {
        return requestTimeoutMs;
    }

    public void setRequestTimeoutMs(Integer requestTimeoutMs) {
        this.requestTimeoutMs = requestTimeoutMs;
    }

    public Integer getMaxConnections() {
        return maxConnections;
    }

    public void setMaxConnections(Integer maxConnections) {
        this.maxConnections = maxConnections;
    }
}
