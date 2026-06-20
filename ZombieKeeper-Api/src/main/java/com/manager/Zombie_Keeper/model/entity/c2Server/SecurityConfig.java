package com.manager.Zombie_Keeper.model.entity.c2Server;

import jakarta.persistence.*;

@Entity
@Table(name = "tb_security_config")
public class SecurityConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "server_id", nullable = false)
    private C2Server server;

    // JWT
    @Column(length = 512)
    private String jwtSecret;

    private Long jwtExpirationMs = 86400000L;      // 24h

    private Long jwtRefreshExpirationMs = 604800000L; // 7 dias

    // Senhas
    private Integer bcryptCost = 12;

    // Proteção de login
    private Integer maxLoginAttempts = 5;

    private Long lockoutDurationMs = 900000L;  // 15min

    // Registro e acesso
    private Boolean allowRegistration = false;

    private Boolean requireEmailVerification = false;

    private Boolean mfaEnabled = false;

    // IP whitelist para operadores (null = sem restrição)
    @Column(length = 512)
    private String allowedOperatorIps;

    public SecurityConfig() {  }
    public SecurityConfig(Long id, C2Server server, String jwtSecret, Long jwtExpirationMs, Long jwtRefreshExpirationMs,
                          Integer bcryptCost, Integer maxLoginAttempts, Long lockoutDurationMs,
                          Boolean allowRegistration, Boolean requireEmailVerification,
                          Boolean mfaEnabled, String allowedOperatorIps) {
        this.id = id;
        this.server = server;
        this.jwtSecret = jwtSecret;
        this.jwtExpirationMs = jwtExpirationMs;
        this.jwtRefreshExpirationMs = jwtRefreshExpirationMs;
        this.bcryptCost = bcryptCost;
        this.maxLoginAttempts = maxLoginAttempts;
        this.lockoutDurationMs = lockoutDurationMs;
        this.allowRegistration = allowRegistration;
        this.requireEmailVerification = requireEmailVerification;
        this.mfaEnabled = mfaEnabled;
        this.allowedOperatorIps = allowedOperatorIps;
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

    public String getJwtSecret() {
        return jwtSecret;
    }

    public void setJwtSecret(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    public Long getJwtExpirationMs() {
        return jwtExpirationMs;
    }

    public void setJwtExpirationMs(Long jwtExpirationMs) {
        this.jwtExpirationMs = jwtExpirationMs;
    }

    public Long getJwtRefreshExpirationMs() {
        return jwtRefreshExpirationMs;
    }

    public void setJwtRefreshExpirationMs(Long jwtRefreshExpirationMs) {
        this.jwtRefreshExpirationMs = jwtRefreshExpirationMs;
    }

    public Integer getBcryptCost() {
        return bcryptCost;
    }

    public void setBcryptCost(Integer bcryptCost) {
        this.bcryptCost = bcryptCost;
    }

    public Integer getMaxLoginAttempts() {
        return maxLoginAttempts;
    }

    public void setMaxLoginAttempts(Integer maxLoginAttempts) {
        this.maxLoginAttempts = maxLoginAttempts;
    }

    public Long getLockoutDurationMs() {
        return lockoutDurationMs;
    }

    public void setLockoutDurationMs(Long lockoutDurationMs) {
        this.lockoutDurationMs = lockoutDurationMs;
    }

    public Boolean getAllowRegistration() {
        return allowRegistration;
    }

    public void setAllowRegistration(Boolean allowRegistration) {
        this.allowRegistration = allowRegistration;
    }

    public Boolean getRequireEmailVerification() {
        return requireEmailVerification;
    }

    public void setRequireEmailVerification(Boolean requireEmailVerification) {
        this.requireEmailVerification = requireEmailVerification;
    }

    public Boolean getMfaEnabled() {
        return mfaEnabled;
    }

    public void setMfaEnabled(Boolean mfaEnabled) {
        this.mfaEnabled = mfaEnabled;
    }

    public String getAllowedOperatorIps() {
        return allowedOperatorIps;
    }

    public void setAllowedOperatorIps(String allowedOperatorIps) {
        this.allowedOperatorIps = allowedOperatorIps;
    }
}
