package com.manager.Zombie_Keeper.model.entity.c2Server;

import jakarta.persistence.*;
@Entity
@Table(name = "tb_port_config")
public class PortConfig {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JoinColumn(name = "network_id")
    @ManyToOne(cascade = CascadeType.ALL)
    private NetworkConfig network;

    private int number;

    @Column(length = 10)
    private String protocol; // TCP, UDP, HTTP, HTTPS, WS, WSS

    private String service; // nome do serviço rodando nesta porta

    private String banner; // banner capturado ou exibido

    private Boolean enabled = true;

    @Column(length = 45)
    private String bindAddress = "0.0.0.0";

    private Boolean isListener = false; // true = listener C2, false = serviço interno

    @Column(length = 256)
    private String description;

    private Integer maxConnections;

    private Boolean sslEnabled = false;

    @Column(length = 512)
    private String certPath;

    @Column(length = 512)
    private String keyPath;

    @OneToOne(mappedBy = "port")
    private WebConfig webConfig;

    @OneToOne(mappedBy = "port")
    private ApiConfig apiConfig;

    @OneToOne(mappedBy = "port")
    private DatabaseConfig dbConfig;

    public PortConfig() {}

    public PortConfig(Long id, NetworkConfig network, int number, String protocol, String service, String banner,
                      Boolean enabled, String bindAddress, Boolean isListener, String description,
                      Integer maxConnections, Boolean sslEnabled, String certPath, String keyPath, WebConfig webConfig,
                      ApiConfig apiConfig, DatabaseConfig dbConfig) {
        this.id = id;
        this.network = network;
        this.number = number;
        this.protocol = protocol;
        this.service = service;
        this.banner = banner;
        this.enabled = enabled;
        this.bindAddress = bindAddress;
        this.isListener = isListener;
        this.description = description;
        this.maxConnections = maxConnections;
        this.sslEnabled = sslEnabled;
        this.certPath = certPath;
        this.keyPath = keyPath;
        this.webConfig = webConfig;
        this.apiConfig = apiConfig;
        this.dbConfig = dbConfig;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public NetworkConfig getNetwork() {
        return network;
    }

    public void setNetwork(NetworkConfig network) {
        this.network = network;
    }

    public int getNumber() {
        return number;
    }

    public void setNumber(int number) {
        this.number = number;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }

    public String getBanner() {
        return banner;
    }

    public void setBanner(String banner) {
        this.banner = banner;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public String getBindAddress() {
        return bindAddress;
    }

    public void setBindAddress(String bindAddress) {
        this.bindAddress = bindAddress;
    }

    public Boolean getListener() {
        return isListener;
    }

    public void setListener(Boolean listener) {
        isListener = listener;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Integer getMaxConnections() {
        return maxConnections;
    }

    public void setMaxConnections(Integer maxConnections) {
        this.maxConnections = maxConnections;
    }

    public Boolean getSslEnabled() {
        return sslEnabled;
    }

    public void setSslEnabled(Boolean sslEnabled) {
        this.sslEnabled = sslEnabled;
    }

    public String getCertPath() {
        return certPath;
    }

    public void setCertPath(String certPath) {
        this.certPath = certPath;
    }

    public String getKeyPath() {
        return keyPath;
    }

    public void setKeyPath(String keyPath) {
        this.keyPath = keyPath;
    }

    public WebConfig getWebConfig() {
        return webConfig;
    }

    public void setWebConfig(WebConfig webConfig) {
        this.webConfig = webConfig;
    }

    public ApiConfig getApiConfig() {
        return apiConfig;
    }

    public void setApiConfig(ApiConfig apiConfig) {
        this.apiConfig = apiConfig;
    }

    public DatabaseConfig getDbConfig() {
        return dbConfig;
    }

    public void setDbConfig(DatabaseConfig dbConfig) {
        this.dbConfig = dbConfig;
    }
}
