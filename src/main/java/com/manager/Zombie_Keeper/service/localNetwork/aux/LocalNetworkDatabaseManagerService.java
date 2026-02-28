package com.manager.Zombie_Keeper.service.localNetwork.aux;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.manager.Zombie_Keeper.model.entity.agent.Agent;
import com.manager.Zombie_Keeper.model.entity.localNetwork.NetworkNode;
import com.manager.Zombie_Keeper.model.entity.localNetwork.NetworkSession;
import com.manager.Zombie_Keeper.model.entity.localNetwork.Port;
import com.manager.Zombie_Keeper.model.entity.localNetwork.Vulnerability;
import com.manager.Zombie_Keeper.repository.agent.AgentRepository;
import com.manager.Zombie_Keeper.repository.localNetwork.NetworkNodeRepository;
import com.manager.Zombie_Keeper.repository.localNetwork.NetworkSessionRepository;
import com.manager.Zombie_Keeper.repository.localNetwork.PortRepository;
import com.manager.Zombie_Keeper.repository.localNetwork.VulnerabilityRepository;
import com.manager.Zombie_Keeper.service.localNetwork.fingerprint.LocalNetworkFingerprintService;

import jakarta.transaction.Transactional;

@Service 
public class LocalNetworkDatabaseManagerService {

    private static final Logger logger = LoggerFactory.getLogger(LocalNetworkDatabaseManagerService.class);

    private final LocalNetworkFingerprintService localNetFp;
    private final NetworkSessionRepository sessionRepository;
    private final PortRepository portRepository;
    private final NetworkNodeRepository networkNodeRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final AgentRepository agentRepository; 

    public LocalNetworkDatabaseManagerService(
            LocalNetworkFingerprintService localNetFp, 
            NetworkSessionRepository sessionRepository,
            PortRepository portRepository, 
            NetworkNodeRepository networkNodeRepository,
            VulnerabilityRepository vulnerabilityRepository,
            AgentRepository agentRepository) {
        
        this.localNetFp = localNetFp;
        this.sessionRepository = sessionRepository;
        this.portRepository = portRepository;
        this.networkNodeRepository = networkNodeRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.agentRepository = agentRepository;
    }

    private boolean checkIfNodeIsAgent(String macAddress) {
        if (macAddress == null || macAddress.isEmpty()) return false;
        
        Optional<Agent> matchingAgent = agentRepository.findByMacAddress(macAddress);
        return matchingAgent.isPresent();
    }
    
   
    public NetworkSession linkNodesInSession(NetworkSession s){
        if(s.getDevices() == null ) return s;

        List<NetworkNode> nodes = s.getDevices();

        for(NetworkNode n: nodes){
            n.setNetwork(s);
            
            if(n.getOpenPorts() != null){
                for(Port p: n.getOpenPorts()){
                    p.setNode(n);
                }
            }

            if(n.getVulnerabilities() != null){
                for(Vulnerability v: n.getVulnerabilities()){
                    v.setNode(n);
                }
            }
        }

        return s;
    }

    @Transactional 
    public NetworkNode updateNode(NetworkSession sessionJSON){
        
        if(sessionJSON == null || sessionJSON.getDevices() == null || sessionJSON.getDevices().isEmpty()) {
            return null;
        }
        
        // Chamada corrigida
        sessionJSON = this.linkNodesInSession(sessionJSON);    
        NetworkNode nodeJSON = sessionJSON.getDevices().get(0);
        
        if(sessionRepository.findByNetworkIdentifier(sessionJSON.getNetworkIdentifier()).isPresent()){
            
            NetworkSession sessionDBA = sessionRepository.findById(
                sessionRepository.findIdByNetworkIdentifier(sessionJSON.getNetworkIdentifier())
            ).get();

            sessionDBA.setLastSeen(LocalDateTime.now());

            NetworkNode nodeDBA = null;
            
            for(NetworkNode n: sessionDBA.getDevices()){
                if(n.getMacAddress().equals(nodeJSON.getMacAddress())) {
                    nodeDBA = n;
                    break;
                }
            }

            if(nodeDBA == null){
                nodeJSON.setFirstSeen(LocalDateTime.now());
                nodeJSON.setLastSeen(LocalDateTime.now());
                nodeJSON.setNetwork(sessionDBA);
                sessionDBA.getDevices().add(nodeJSON);

                return nodeJSON;
            }

            nodeDBA.setLastSeen(LocalDateTime.now());
            nodeDBA.setIpv4(nodeJSON.getIpv4());
            nodeDBA.setIpv6(nodeJSON.getIpv6());
            nodeDBA.setHostname(nodeJSON.getHostname());
            nodeDBA.setOs(nodeJSON.getOs());
            nodeDBA.setArchitecture(nodeJSON.getArchitecture());
            nodeDBA.setStatus(nodeJSON.getStatus() != null ? nodeJSON.getStatus() : "SCANNED");
            nodeDBA.setVendor(nodeJSON.getVendor());
            nodeDBA.setTrusted(nodeJSON.isTrusted()); 
            nodeDBA.setVulnerabilityScore(nodeJSON.getVulnerabilityScore());

            nodeDBA.setAgent(checkIfNodeIsAgent(nodeDBA.getMacAddress()));

            Map<Integer, Port> mapPortsDBA = new HashMap<>();
            for(Port p: nodeDBA.getOpenPorts()) mapPortsDBA.put(p.getNumber(), p);
            
            List<Port> portsJSON = nodeJSON.getOpenPorts();
            List<Port> portsRemove = new ArrayList<>();

            for(Port p: portsJSON ){
                Integer portIntJSON = p.getNumber();

                if(mapPortsDBA.containsKey(portIntJSON)){
                    Port portUpdateDBA = mapPortsDBA.get(portIntJSON);
                    mapPortsDBA.remove(portIntJSON);
                    
                    portUpdateDBA.setProtocol(p.getProtocol());
                    portUpdateDBA.setService(p.getService());
                    portUpdateDBA.setBanner(p.getBanner());
                }else{
                    p.setNode(nodeDBA);
                    nodeDBA.getOpenPorts().add(p);
                }
            }

            for(Port stalePort : mapPortsDBA.values()){
                logger.debug("Starting local scan on port: {} for ip: {}", stalePort.getNumber(), nodeDBA.getIpv4());
                
                int resultPortScan = localNetFp.excLocalPortScan(
                    "LocalFingerPrint", 
                    sessionDBA.getNetworkIdentifier(), 
                    nodeDBA.getMacAddress(), 
                    nodeDBA.getIpv4(), 
                    String.valueOf(stalePort.getNumber()), 
                    "2", 
                    "0"
                );

                logger.debug("Port scan result: {}", resultPortScan);

                if(resultPortScan == 2){
                    logger.info("Stale port {} confirmed closed. Removing from db.", stalePort.getNumber());
                    portsRemove.add(stalePort);
                }
            }

            nodeDBA.getOpenPorts().removeAll(portsRemove);

            Map<String, Vulnerability> mapVulnerabilityDBA = new HashMap<>();
            for(Vulnerability v: nodeDBA.getVulnerabilities()) mapVulnerabilityDBA.put(v.getCve(), v);
            List<Vulnerability> vulnerabilitiesJSON = nodeJSON.getVulnerabilities();

            for(Vulnerability v: vulnerabilitiesJSON){
                String cveJSON = v.getCve();

                if(mapVulnerabilityDBA.containsKey(cveJSON)){
                    Vulnerability vulnerabilityUpdateDBA = mapVulnerabilityDBA.get(cveJSON);
                    mapVulnerabilityDBA.remove(cveJSON);

                    vulnerabilityUpdateDBA.setName(v.getName());
                    vulnerabilityUpdateDBA.setTitle(v.getTitle());
                    vulnerabilityUpdateDBA.setSeverity(v.getSeverity());
                    vulnerabilityUpdateDBA.setDescription(v.getDescription());
                }else{
                    v.setNode(nodeDBA);
                    nodeDBA.getVulnerabilities().add(v);
                }
            }

            nodeDBA.getVulnerabilities().removeAll(mapVulnerabilityDBA.values());
            
            return nodeDBA;

        }else{
            return null;
        }
    }

    @Transactional 
    public NetworkSession updateCompleteSession(NetworkSession sessionJSON){
        NetworkSession sessionDBA = new NetworkSession();
        
        sessionJSON = this.linkNodesInSession(sessionJSON);
       
        if(sessionRepository.findByNetworkIdentifier(sessionJSON.getNetworkIdentifier()).isPresent()){
            
            sessionDBA = sessionRepository.findById(
                sessionRepository.findIdByNetworkIdentifier(sessionJSON.getNetworkIdentifier())
            ).get();

            List<NetworkNode> nodesDBA = sessionDBA.getDevices();
            List<NetworkNode> nodesJSON = sessionJSON.getDevices();

            Map<String, NetworkNode> mapNodesDBA = new HashMap<>();

            for(NetworkNode n: nodesDBA){
                if(n.getMacAddress() != null) mapNodesDBA.put(n.getMacAddress(), n);
            }

            sessionDBA.setLastSeen(LocalDateTime.now());
            sessionDBA.setGatewayIp(sessionJSON.getGatewayIp());
            
            for(NetworkNode n: nodesJSON){
                String macNodeJSON = n.getMacAddress();

                if(mapNodesDBA.containsKey(macNodeJSON)){
                    
                    NetworkNode nodeUpdateDBA  = mapNodesDBA.get(macNodeJSON);
                    mapNodesDBA.remove(macNodeJSON);

                    nodeUpdateDBA.setLastSeen(LocalDateTime.now());
                    nodeUpdateDBA.setIpv4(n.getIpv4());
                    nodeUpdateDBA.setIpv6(n.getIpv6());
                    nodeUpdateDBA.setHostname(n.getHostname());
                    nodeUpdateDBA.setVendor(n.getVendor());
                    nodeUpdateDBA.setOs(n.getOs());
                    nodeUpdateDBA.setArchitecture(n.getArchitecture());
                    nodeUpdateDBA.setStatus(n.getStatus() != null ? n.getStatus() : "SCANNED");
                    nodeUpdateDBA.setTrusted(n.isTrusted());
                    nodeUpdateDBA.setVulnerabilityScore(n.getVulnerabilityScore());
                    
                    nodeUpdateDBA.setAgent(checkIfNodeIsAgent(nodeUpdateDBA.getMacAddress()));
                    
                    Map<Integer, Port> mapNodesPortsDBA = new HashMap<>();
                    List<Port> portsUpdateDBA = nodeUpdateDBA.getOpenPorts();
                    List<Port> portsUpdateJSON = n.getOpenPorts();
                    
                    for(Port p: portsUpdateDBA){mapNodesPortsDBA.put(p.getNumber(), p);}
            
                    List<Port> portsRemove = new ArrayList<>();

                    for(Port p: portsUpdateJSON){
                        Integer portNumberJSON = p.getNumber();

                        if(mapNodesPortsDBA.containsKey(portNumberJSON)){
                            Port portUpdateDBA =  mapNodesPortsDBA.get(portNumberJSON);
                            mapNodesPortsDBA.remove(portNumberJSON);

                            portUpdateDBA.setProtocol(p.getProtocol());
                            portUpdateDBA.setService(p.getService());
                            portUpdateDBA.setBanner(p.getBanner());
                        } else{
                            p.setNode(nodeUpdateDBA);
                            nodeUpdateDBA.getOpenPorts().add(p);
                        }
                    }

                    for(Port stalePort : mapNodesPortsDBA.values()){
                        logger.debug("Starting local scan on port: {} ip: {}", stalePort.getNumber(), nodeUpdateDBA.getIpv4());                       
                        
                        int resultPortScan = localNetFp.excLocalPortScan(
                            "LocalFingerPrint", 
                            sessionDBA.getNetworkIdentifier(), 
                            nodeUpdateDBA.getMacAddress(), 
                            nodeUpdateDBA.getIpv4(), 
                            String.valueOf(stalePort.getNumber()), 
                            "2", 
                            "0"
                        );

                        logger.debug("Port scan result: {}", resultPortScan);

                        if(resultPortScan == 2){
                            logger.info("Stale port {} confirmed closed. Removing.", stalePort.getNumber());
                            portsRemove.add(stalePort);
                        }
                    }

                    nodeUpdateDBA.getOpenPorts().removeAll(portsRemove);
                    
                    Map<String, Vulnerability> mapNodesVulnerability = new HashMap<>();
                    List<Vulnerability> vulnerabilitiesUpdateDBA = nodeUpdateDBA.getVulnerabilities();
                    List<Vulnerability> vulnerabilitiesUpdateJSON = n.getVulnerabilities();
                    
                    for(Vulnerability v: vulnerabilitiesUpdateDBA){mapNodesVulnerability.put(v.getCve(), v);}

                    for(Vulnerability v: vulnerabilitiesUpdateJSON){
                        String cveJSON = v.getCve();

                        if(mapNodesVulnerability.containsKey(cveJSON)){
                            Vulnerability vulnerabilityUpdateDBA = mapNodesVulnerability.get(cveJSON);
                            mapNodesVulnerability.remove(cveJSON);

                            vulnerabilityUpdateDBA.setName(v.getName());
                            vulnerabilityUpdateDBA.setTitle(v.getTitle());
                            vulnerabilityUpdateDBA.setSeverity(v.getSeverity());
                            vulnerabilityUpdateDBA.setDescription(v.getDescription());
                        }else{
                            v.setNode(nodeUpdateDBA);
                            nodeUpdateDBA.getVulnerabilities().add(v);
                        }
                    }
                    
                    nodeUpdateDBA.getVulnerabilities().removeAll(mapNodesVulnerability.values());

                }else{
                    n.setFirstSeen(LocalDateTime.now());
                    n.setLastSeen(LocalDateTime.now());
                    n.setNetwork(sessionDBA);
                    sessionDBA.getDevices().add(n);
                }
            }
            
            sessionDBA.getDevices().removeAll(mapNodesDBA.values());
            
            logger.info("-- SESSION UPDATED --");
            return sessionDBA;

        }else{
            logger.info("-- NEW SESSION CREATED --");
            
            sessionJSON.setFirstSeen(LocalDateTime.now());
            sessionJSON.setLastSeen(LocalDateTime.now());
            
            if(sessionJSON.getDevices() != null) {
                for(NetworkNode n : sessionJSON.getDevices()) {
                    n.setFirstSeen(LocalDateTime.now());
                    n.setLastSeen(LocalDateTime.now());
                }
            }

            return sessionJSON;
        }
    }
}