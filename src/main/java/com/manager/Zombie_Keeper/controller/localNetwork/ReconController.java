package com.manager.Zombie_Keeper.controller.localNetwork;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.http.MediaType;

import com.manager.Zombie_Keeper.model.entity.localNetwork.NetworkSession;

import com.manager.Zombie_Keeper.repository.localNetwork.NetworkSessionRepository;
import com.manager.Zombie_Keeper.service.localNetwork.aux.LocalNetworkDatabaseManagerService;
import com.manager.Zombie_Keeper.service.localNetwork.fingerprint.LocalNetworkFingerprintService;

import tools.jackson.databind.ObjectMapper;

@RestController
@RequestMapping("/c2-server/local-network/recon")
public class ReconController {

    LocalNetworkFingerprintService localNetFp;
    NetworkSessionRepository sessionRepository;
    LocalNetworkDatabaseManagerService auxNetworkAuxsService;


    public ReconController(LocalNetworkFingerprintService localNetFp, NetworkSessionRepository sessionRepository,  LocalNetworkDatabaseManagerService auxNetworkAuxsService ){
        this.localNetFp = localNetFp;
        this.sessionRepository = sessionRepository;
        this.auxNetworkAuxsService = auxNetworkAuxsService;
    }
    
    /*
    *  use sec usec for struct timeval(c++) non-bloking io configuration
    *  Ex: "LocalFingerPrint", "all or any ", "0", "300000"
    */
    @GetMapping(value = "/session/{binaryName}/{flag}/{sec}/{usec}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> sessionRecon(@PathVariable String binaryName, @PathVariable String flag, 
        @PathVariable String sec, @PathVariable String usec){

        String json = localNetFp.excLocalNetFingerPrint(binaryName, flag, sec, usec);

        System.out.printf("JSON output for flag: %s: %s ", flag, json);

        try {
       
        
            ObjectMapper mapper = new ObjectMapper();

            NetworkSession sessionEntity = mapper.readValue(json, NetworkSession.class);
            
            sessionEntity = auxNetworkAuxsService.updateCompleteSession(sessionEntity);

            sessionRepository.save(sessionEntity);
            

        } catch (Exception e) {

            System.out.println("Error " +  e.getMessage());
        }

        return ResponseEntity.ok(json);
    }  

    @GetMapping(value = "/node/{binaryName}/{ip}/{mac}/{networkIdentfier}/{flag}/{sec}/{usec}" )
    public ResponseEntity<String> nodeRecon(@PathVariable String binaryName, @PathVariable String networkIdentfier, 
        @PathVariable String ip, @PathVariable String flag, @PathVariable String sec, @PathVariable String usec
    ){
    
        String json =new String();
        
        return ResponseEntity.ok(json);
    }

    @DeleteMapping("/admin/reset-database")
    public ResponseEntity<String> nukeDatabase() {
    
        sessionRepository.deleteAll();
    
        return ResponseEntity.ok("💥 Clear DBA!");
    }

}
