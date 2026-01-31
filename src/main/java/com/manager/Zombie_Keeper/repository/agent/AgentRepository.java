package com.manager.Zombie_Keeper.repository.agent;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.manager.Zombie_Keeper.model.entity.agent.Agent;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AgentRepository extends JpaRepository<Agent, UUID> {

    Optional<Agent> findByIp(String ip);
    
}
