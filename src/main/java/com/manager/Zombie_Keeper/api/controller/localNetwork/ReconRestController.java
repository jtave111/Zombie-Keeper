package com.manager.Zombie_Keeper.api.controller.localNetwork;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import org.springframework.http.MediaType;

import com.manager.Zombie_Keeper.api.controller.auth.AuthRestController;
import com.manager.Zombie_Keeper.model.entity.localNetwork.NetworkNode;
import com.manager.Zombie_Keeper.model.entity.localNetwork.NetworkSession;
import com.manager.Zombie_Keeper.repository.localNetwork.NetworkNodeRepository;
import com.manager.Zombie_Keeper.repository.localNetwork.NetworkSessionRepository;
import com.manager.Zombie_Keeper.service.localNetwork.aux.LocalNetworkDatabaseManagerService;
import com.manager.Zombie_Keeper.service.localNetwork.fingerprint.LocalNetworkFingerprintService;
import com.manager.Zombie_Keeper.service.processManagerService.ProcessManagerService;


import jakarta.servlet.http.HttpServletRequest;
import tools.jackson.databind.ObjectMapper;


@RestController
@RequestMapping("/c2-server/local-network/recon")
public class ReconRestController {
    
    LocalNetworkFingerprintService localNetFp;
    LocalNetworkDatabaseManagerService auxNetworkAuxsService;
    ProcessManagerService processManagerService;
    
    NetworkSessionRepository sessionRepository;
    NetworkNodeRepository networkNodeRepository;
   
    AuthRestController authController;

    public ReconRestController(LocalNetworkFingerprintService localNetFp, NetworkSessionRepository sessionRepository, 
        LocalNetworkDatabaseManagerService auxNetworkAuxsService, NetworkNodeRepository networkNodeRepository, 
        AuthRestController authController, ProcessManagerService processManagerService){
        
            this.localNetFp = localNetFp;
            this.sessionRepository = sessionRepository;
            this.auxNetworkAuxsService = auxNetworkAuxsService;
            this.networkNodeRepository = networkNodeRepository;
            this.authController = authController;
            this.processManagerService = processManagerService;
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
                System.out.println("Node off delete: ." + " mac:" + nodeDBA.get().getMacAddress() + " ip: " + nodeDBA.get().getIpv4());
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

    //TODO formalizar isso 
    //Localhost = http://localhost:8080/ or http://l92.168.x.x:8080/
    //http://localhost:8080/c2-server/local-network/recon/automation/python/start-recon/request.py?localHost=http://localhost:8080&pathScan=/c2-server/local-network/recon/session/LocalFingerPrint/any/0/300000
    @GetMapping(value = "/automation/python/start-recon/{script}")
    public ResponseEntity<String> requestAutomation(HttpServletRequest request, @PathVariable String script, @RequestParam String localHost,@RequestParam String pathScan){  

        
        String JSESSIONID = authController.getHttpSessionId(request).getBody();
        
        String completeUrlScan = localHost + pathScan;

        System.out.println("Url: " +  completeUrlScan );

        CompletableFuture.runAsync(() -> {

            String resultScript = localNetFp.execRequestAutomation(script, JSESSIONID, completeUrlScan);
            System.out.println(" Automação [" + script + "] foi encerrada. Saída: " + resultScript);
        });
        


        return ResponseEntity.ok("Autmoação iniciada em background");
    }


    @DeleteMapping(value = "/automation/python/stop/{script}")
    public ResponseEntity<String> stopProcess(@PathVariable String script) {  

        
        boolean wasKilled = processManagerService.killProcess(script, localNetFp.getActiveProcesses());

        if (wasKilled) {
            return ResponseEntity.ok(" Automação [" + script + "] foi encerrada com sucesso");
        } else {
            return ResponseEntity.status(404).body(" Nenhuma automação rodando com o nome [" + script + "]");
        }
    }

    @DeleteMapping("/admin/reset-database")
    public ResponseEntity<String> nukeDatabase() {
    
        sessionRepository.deleteAll();
    
        return ResponseEntity.ok(" Clear DBA!");
    }

}
