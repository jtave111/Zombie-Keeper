
package com.manager.Zombie_Keeper.model.entity.agent;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import com.manager.Zombie_Keeper.model.enums.agent.Flags;
import com.manager.Zombie_Keeper.model.enums.agent.Tags;




@Entity
public class Agent {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    private UUID id;

    
    @Column(unique = true, nullable = false, updatable = false)
    private Long publicId;

    private String hostname;

    private String os;

    private LocalDateTime lastSeen;

    @OneToMany(mappedBy = "agent", cascade = CascadeType.ALL)
    private List<Loot> loots = new ArrayList<>();

    private String ip;

    @Column(length = 500)
    private Set<Flags> flags;
    
    @Column(length = 500)
    private Set<Tags> tags;

    public Agent(){

    }

    @PrePersist
    public void onCreate(){

        if(this.publicId == null){

            this.publicId = ThreadLocalRandom.current().nextLong(10000000, 99999999);
        }

        if(this.lastSeen == null){           
            
            this.lastSeen =LocalDateTime.now();
            
        }
    }

    
    public Long getPublicId(){
        return publicId;
    }

    public void setPublicId(Long publicId){

        this.publicId = publicId;
    }

    public Set<Tags> getTags(){
        return tags;
    }

    public void setTgas(Set<Tags> tags){

        this.tags = tags;

    }

    public Set<Flags> getFlags(){
       
        return flags;
    }

    public void setFlags(Set<Flags> flags){
        this.flags = flags;
    }
    
    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getOs() {
        return os;
    }

    public void setOs(String os) {
        this.os = os;
    }

    public LocalDateTime getLastSeen() {
        return lastSeen;
    }

    public void setLastSeen(LocalDateTime lastSeen) {
        this.lastSeen = lastSeen;
    }

    public List<Loot> getLoots() {
        return loots;
    }

    public void setLoots(List<Loot> loots) {
        this.loots = loots;
    }

}
