package com.manager.Zombie_Keeper.model.entity.c2Server;

import jakarta.persistence.*;

@Entity
@Table(name = "tb_db_config")
public class DatabaseConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "server_id")
    private C2Server server;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "port_id")
    private PortConfig port;

    @Column(length = 20)
    private String databaseType = "MYSQL"; // MYSQL, POSTGRESQL, SQLITE, H2

    private String host = "localhost";

    private String databaseName;

    private String username;

    private String password;

    @Column(length = 512)
    private String connectionUrl; // JDBC URL completa (sobrescreve host/port/name se preenchida)

    @Column(name = "db_schema")
    private String schema;

    private Boolean sslEnabled = false;

    private Boolean enabled = true;

    // Pool de conexões
    private Integer maxPoolSize = 10;

    private Integer minPoolSize = 2;

    private Integer connectionTimeoutMs = 30000;

    private Integer idleTimeoutMs = 600000;

    public DatabaseConfig() {}

    public DatabaseConfig(Long id, C2Server server, PortConfig port, String databaseType, String host,
                          String databaseName, String username, String password, String connectionUrl, String schema,
                          Boolean sslEnabled, Boolean enabled, Integer maxPoolSize, Integer minPoolSize,
                          Integer connectionTimeoutMs, Integer idleTimeoutMs) {
        this.id = id;
        this.server = server;
        this.port = port;
        this.databaseType = databaseType;
        this.host = host;
        this.databaseName = databaseName;
        this.username = username;
        this.password = password;
        this.connectionUrl = connectionUrl;
        this.schema = schema;
        this.sslEnabled = sslEnabled;
        this.enabled = enabled;
        this.maxPoolSize = maxPoolSize;
        this.minPoolSize = minPoolSize;
        this.connectionTimeoutMs = connectionTimeoutMs;
        this.idleTimeoutMs = idleTimeoutMs;
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

    public String getDatabaseType() {
        return databaseType;
    }

    public void setDatabaseType(String databaseType) {
        this.databaseType = databaseType;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getDatabaseName() {
        return databaseName;
    }

    public void setDatabaseName(String databaseName) {
        this.databaseName = databaseName;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getConnectionUrl() {
        return connectionUrl;
    }

    public void setConnectionUrl(String connectionUrl) {
        this.connectionUrl = connectionUrl;
    }

    public String getSchema() {
        return schema;
    }

    public void setSchema(String schema) {
        this.schema = schema;
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

    public Integer getMaxPoolSize() {
        return maxPoolSize;
    }

    public void setMaxPoolSize(Integer maxPoolSize) {
        this.maxPoolSize = maxPoolSize;
    }

    public Integer getMinPoolSize() {
        return minPoolSize;
    }

    public void setMinPoolSize(Integer minPoolSize) {
        this.minPoolSize = minPoolSize;
    }

    public Integer getConnectionTimeoutMs() {
        return connectionTimeoutMs;
    }

    public void setConnectionTimeoutMs(Integer connectionTimeoutMs) {
        this.connectionTimeoutMs = connectionTimeoutMs;
    }

    public Integer getIdleTimeoutMs() {
        return idleTimeoutMs;
    }

    public void setIdleTimeoutMs(Integer idleTimeoutMs) {
        this.idleTimeoutMs = idleTimeoutMs;
    }
}
