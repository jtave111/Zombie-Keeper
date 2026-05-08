package com.manager.Zombie_Keeper.repository.agent;

import com.manager.Zombie_Keeper.model.entity.agent.AgentLocation;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AgentLocationRepository  extends JpaRepository<AgentLocation, Long> {

    // ultima location do agent expecifico
    Optional<AgentLocation> findTopByAgentIdOrderByCapturedAtDesc(UUID agentId);

    // historicorico completo de um agente para trilha no mapa
    List<AgentLocation> findByAgentIdOrderByCapturedAtAsc(UUID agentId);

    // ultima localização de todos os agentes (para o WorldMap)
    @org.springframework.data.jpa.repository.Query("""
        SELECT al FROM AgentLocation al
        WHERE al.capturedAt = (
            SELECT MAX(al2.capturedAt)
            FROM AgentLocation al2
            WHERE al2.agent.id = al.agent.id
        )
    """)
    List<AgentLocation> findLatestForAllAgents();
}
