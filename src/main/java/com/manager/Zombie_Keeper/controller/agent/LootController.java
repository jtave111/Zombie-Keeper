package com.manager.Zombie_Keeper.controller.agent;


import com.manager.Zombie_Keeper.model.entity.agent.Agent;
import com.manager.Zombie_Keeper.model.entity.agent.Loot;
import com.manager.Zombie_Keeper.repository.agent.AgentRepository;
import com.manager.Zombie_Keeper.repository.agent.LootRepository;

import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/c2-server/loots")
public class LootController {

    private final LootRepository lootRepository;
    private final AgentRepository agentRepository;

    public LootController(LootRepository lootRepository, AgentRepository agentRepository) {
        this.lootRepository = lootRepository;
        this.agentRepository = agentRepository;
    }

    @PostMapping("/{agent_id}")
    public Loot reportLoot(@PathVariable UUID agentId, @RequestBody Loot newLoot){

        Agent owner = agentRepository.findById(agentId).orElse(null);

        if(owner != null){

            newLoot.setAgent(owner);

            return lootRepository.save(newLoot);

        }
        return null;
    }

}
