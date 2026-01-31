package com.manager.Zombie_Keeper.service.localNetwork.aux;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


import org.springframework.stereotype.Service;

import com.manager.Zombie_Keeper.model.entity.localNetwork.NetworkNode;
import com.manager.Zombie_Keeper.model.entity.localNetwork.NetworkSession;
import com.manager.Zombie_Keeper.model.entity.localNetwork.Port;
import com.manager.Zombie_Keeper.model.entity.localNetwork.Vulnerability;
import com.manager.Zombie_Keeper.repository.localNetwork.NetworkNodeRepository;
import com.manager.Zombie_Keeper.repository.localNetwork.NetworkSessionRepository;
import com.manager.Zombie_Keeper.repository.localNetwork.PortRepository;
import com.manager.Zombie_Keeper.repository.localNetwork.VulnerabilityRepository;
import com.manager.Zombie_Keeper.service.localNetwork.fingerprint.LocalNetworkFingerprintService;

import jakarta.transaction.Transactional;

@Service
public class LocalNetworkDatabaseManagerService {

    LocalNetworkFingerprintService localNetFp;
    NetworkSessionRepository sessionRepository;
    PortRepository portRepository;
    NetworkNodeRepository networkNodeRepository;
    VulnerabilityRepository vulnerabilityRepository;


    public LocalNetworkDatabaseManagerService(LocalNetworkFingerprintService localNetFp, NetworkSessionRepository sessionRepository,
        PortRepository portRepository, NetworkNodeRepository networkNodeRepository,
        VulnerabilityRepository vulnerabilityRepository
    ){
        this.localNetFp = localNetFp;
        this.sessionRepository = sessionRepository;
        this.portRepository = portRepository;
        this.networkNodeRepository = networkNodeRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
    }

    //for linking 
    public NetworkSession linkigNodesInSession(NetworkSession s){

        if(s.getDevices() == null ) return s;


        List<NetworkNode> nodes = s.getDevices();

        for(NetworkNode n: nodes){

            n.setNetwork(s);
            
            if(n.getOpenPorts() != null){

                List<Port> ports = n.getOpenPorts();

                for(Port p: ports){

                    p.setNode(n);
                }

            }

        }

        return s;
    }


    //for update
    @Transactional 
    public NetworkSession updateCompleteSession( NetworkSession sessionJSON){
        NetworkSession sessionDBA = new NetworkSession();
        
        sessionJSON = this.linkigNodesInSession(sessionJSON);
       
        if(sessionRepository.findByNetworkIdentifier(sessionJSON.getNetworkIdentifier()).isPresent()){
            
            sessionDBA = sessionRepository.findById(
                sessionRepository.findIdByNetworkIdentifier(sessionJSON.getNetworkIdentifier())
            ).get();

            List<NetworkNode> nodesDBA = sessionDBA.getDevices();
            List<NetworkNode> nodesJSON = sessionJSON.getDevices();


            Map<String, NetworkNode> mapNodesDBA = new HashMap<>();

            for(NetworkNode n: nodesDBA){if(n.getMacAddress() != null) mapNodesDBA.put(n.getMacAddress(), n);}


            sessionDBA.setLastSeen(LocalDateTime.now());
            sessionDBA.setGatewayIp(sessionJSON.getGatewayIp());
           
            
            for(NetworkNode n: nodesJSON){

                String macNodeJSON = n.getMacAddress();

                if(mapNodesDBA.containsKey(macNodeJSON)){
                    
                    NetworkNode nodeUpdateDBA  = mapNodesDBA.get(macNodeJSON);
                    
                    mapNodesDBA.remove(macNodeJSON);

                    nodeUpdateDBA.setIpAddress(n.getIpAddress());
                    nodeUpdateDBA.setHostname(n.getHostname());
                    nodeUpdateDBA.setVendor(n.getVendor());
                    nodeUpdateDBA.setOs(n.getOs());
                    nodeUpdateDBA.setTrusted(n.isTrusted());
                    nodeUpdateDBA.setVunerabilityScore(n.getVunerabilityScore());
                    
                    Map<Integer, Port> mapNodesPortsDBA = new HashMap<>();

                    List<Port> portsUpdateDBA = nodeUpdateDBA.getOpenPorts();
                    List<Port> portsUpdateJSON = n.getOpenPorts();
                    for(Port p: portsUpdateDBA){mapNodesPortsDBA.put(p.getNumber(), p);}
            
                    for(Port p: portsUpdateJSON){
                        Integer portNumberJSON = p.getNumber();

                        if(mapNodesPortsDBA.containsKey(portNumberJSON)){

                            Port portUpdateDBA =  mapNodesPortsDBA.get(portNumberJSON);
                            
                            //Para atualizar portas que foram fechadas
                            mapNodesPortsDBA.remove(portNumberJSON);


                            portUpdateDBA.setProtocol(p.getProtocol());
                            portUpdateDBA.setService(p.getService());
                            portUpdateDBA.setBanner(p.getBanner());

                            
                        } 
                        else{
                            p.setNode(nodeUpdateDBA);
                            nodeUpdateDBA.getOpenPorts().add(p);
                        }
                    
                    }


                    //Para atualizar portas que foram fechadas
                    nodeUpdateDBA.getOpenPorts().removeAll(mapNodesPortsDBA.values());

                    Map<String, Vulnerability> mapNodesVulnerability = new HashMap<>();
                    List<Vulnerability> vulnerabilitiesUpdateDBA = nodeUpdateDBA.getVulnerabilitys();
                    List<Vulnerability> vulnerabilitiesUpdateJSON = n.getVulnerabilitys();
                    for(Vulnerability v: vulnerabilitiesUpdateDBA){mapNodesVulnerability.put(v.getCve(), v);}


                    for(Vulnerability v: vulnerabilitiesUpdateJSON){

                        String cveJSON = v.getCve();


                        if(mapNodesVulnerability.containsKey(cveJSON)){
                            
                            Vulnerability vulnerabilityUpdateDBA = mapNodesVulnerability.get(cveJSON);

                            //Para atualizar vunl  que foram tratadas
                            mapNodesVulnerability.remove(cveJSON);


                            vulnerabilityUpdateDBA.setName(v.getName());
                            vulnerabilityUpdateDBA.setTitle(v.getTitle());
                            vulnerabilityUpdateDBA.setSeverity(v.getSeverity());
                            vulnerabilityUpdateDBA.setDescription(v.getDescription());

                        }else{


                            v.setNode(nodeUpdateDBA);
                            nodeUpdateDBA.getVulnerabilitys().add(v);
                        }
                        
                    }
                    
                    //Para atualizar vunl  que foram tratadas
                    nodeUpdateDBA.getVulnerabilitys().removeAll(mapNodesVulnerability.values());

                }else{
                    //new node (insert)
                    n.setNetwork(sessionDBA);
                    sessionDBA.getDevices().add(n);
                }

            }
            
            sessionDBA.getDevices().removeAll(mapNodesDBA.values());

        }else{

            System.out.println("--CREATE--");
            return sessionJSON;

        }


        System.out.println("--UPDATE--");
        return sessionDBA;
    }


}
