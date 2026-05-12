package com.manager.Zombie_Keeper.controller.agent;
import com.manager.Zombie_Keeper.dtos.agent.AgentDtos;
import com.manager.Zombie_Keeper.dtos.agent.AgentGeoDto;
import com.manager.Zombie_Keeper.exception.DuplicateAgentException;
import com.manager.Zombie_Keeper.model.entity.agent.Agent;
import com.manager.Zombie_Keeper.repository.agent.AgentRepository;
import com.manager.Zombie_Keeper.service.agents.AgentLocationService;
import com.manager.Zombie_Keeper.service.agents.AgentsService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/c2-server/agents")
public class AgentRestController {

    @Autowired
    private final AgentRepository agentRepository;
    @Autowired
    private final AgentLocationService agentLocationService;
    @Autowired
    private final AgentsService agentsService;

    public AgentRestController(AgentRepository agentRepository, AgentLocationService agentLocationService, AgentsService agentsService) {
        this.agentRepository = agentRepository;
        this.agentLocationService = agentLocationService;
        this.agentsService = agentsService;
    }


    //TODO: Implementar dto do agent
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
    @PostMapping("/register")
    public ResponseEntity<String> registerAgent(@RequestBody AgentDtos dto){


        if(( agentRepository.findByMacAddress(dto.getMacAddress()).isEmpty()) ){
            //CREATE

            Agent newAgent = new Agent();
            newAgent.setHostname(dto.getHostname());
            newAgent.setOs(dto.getOs());
            newAgent.setArchitecture(dto.getArchitecture());
            newAgent.setLoggedUser(dto.getLoggedUser());
            newAgent.setIsElevated(dto.getIsElevated());
            newAgent.setIpv4(dto.getIpv4());
            newAgent.setIpv6(dto.getIpv6());
            newAgent.setMacAddress(dto.getMacAddress());
            newAgent.setFirstSeen(LocalDateTime.now());
            newAgent.setLastSeen(LocalDateTime.now());
            newAgent.addLocation(agentLocationService.agentDefineLocation(dto));
            agentsService.setPreInformation(newAgent);
            agentRepository.save(newAgent);
            return ResponseEntity.status(HttpStatus.CREATED).body("Agent register");


        }else{
            //UPDATE
            Agent agent = agentRepository.findByMacAddress(dto.getMacAddress()).get();
            agent.setHostname(dto.getHostname());
            agent.setOs(dto.getOs());
            agent.setArchitecture(dto.getArchitecture());
            agent.setLoggedUser(dto.getLoggedUser());
            agent.setIsElevated(dto.getIsElevated());
            agent.setIpv4(dto.getIpv4());
            agent.setIpv6(dto.getIpv6());
            agent.setMacAddress(dto.getMacAddress());
            agent.setLastSeen(LocalDateTime.now());
            agent.addLocation(agentLocationService.agentDefineLocation(dto));
            agentRepository.save(agent);

            return ResponseEntity.ok(" ");

        }


    }

    /*
    @GetMapping("/geo")
    public List<AgentGeoDto> getAgentGeo() {
        return agentRepository.findAll().stream()
            .map(agentLocationService.agentDefineLocation(Agent))
            .toList();
    }

     */



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