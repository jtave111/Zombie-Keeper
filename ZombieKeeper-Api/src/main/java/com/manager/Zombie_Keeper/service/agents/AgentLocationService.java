package com.manager.Zombie_Keeper.service.agents;

import com.manager.Zombie_Keeper.dtos.agent.AgentDtos;
import com.manager.Zombie_Keeper.model.entity.agent.Agent;
import com.manager.Zombie_Keeper.model.entity.agent.AgentLocation;
import com.manager.Zombie_Keeper.model.enums.agent.LocationSource;
import org.springframework.stereotype.Service;

@Service
public class AgentLocationService {

    public AgentLocation agentDefineLocation(AgentDtos dtoAgtent) {

        double lat =  0.0;
        double lng = 0.0;
        String country = "Unknown";
        String city    = "Unknown";
        LocationSource source  = LocationSource.UNKNOWN;

        AgentLocation agentLocation = new AgentLocation();

        // Prioridade 1 — localização real enviada pelo agente
        if (dtoAgtent.getLat() != null && dtoAgtent.getLng() != null) {
            lat     = dtoAgtent.getLat();
            lng     = dtoAgtent.getLng();
            city    = dtoAgtent.getCity()    != null ? dtoAgtent.getCity()    : "Unknown";
            country = dtoAgtent.getCountry() != null ? dtoAgtent.getCountry() : "Unknown";
            source  = dtoAgtent.getLocationSource() != null ?
                    LocationSource.valueOf(dtoAgtent.getLocationSource()) : LocationSource.DEVICE;

            // Prioridade 2 — fallback por IP (MaxMind ou ip-api)
        } else if (dtoAgtent.getIpv4() != null && !isPrivateIp(dtoAgtent.getIpv4())) {
            try {
                fallbackForIp(agentLocation);

            } catch (Exception ignored) {}
        }

        return agentLocation;
    }


    private void fallbackForIp(AgentLocation location){

        //TODO: implemntar interação com a ip-api em primeira instancia
        Agent agent = location.getAgent();

        if (agent.getIpv4() != null && !agent.getIpv4().isBlank()) {
            String[] parts = agent.getIpv4().split("\\.");
            if (parts.length == 4) {
                try {
                    int a = Integer.parseInt(parts[0]);
                    int b = Integer.parseInt(parts[1]);
                    double lat = ((a % 180) - 90) + (b / 255.0);
                    double lng = ((a % 360) - 180) + ((255 - b) / 255.0);
                    location.setCity("Unknown");
                    location.setCountry("Unknown");
                    location.setLat(lat);
                    location.setLng(lng);

                } catch (NumberFormatException ignored) {}
            }
        }

        location.setSource(LocationSource.IP);
    }
    private boolean isPrivateIp(String ip) {
        return ip.startsWith("10.")
                || ip.startsWith("192.168.")
                || ip.startsWith("172.16.")  || ip.startsWith("172.17.")
                || ip.startsWith("172.18.")  || ip.startsWith("172.19.")
                || ip.startsWith("172.20.")  || ip.startsWith("172.21.")
                || ip.startsWith("172.22.")  || ip.startsWith("172.23.")
                || ip.startsWith("172.24.")  || ip.startsWith("172.25.")
                || ip.startsWith("172.26.")  || ip.startsWith("172.27.")
                || ip.startsWith("172.28.")  || ip.startsWith("172.29.")
                || ip.startsWith("172.30.")  || ip.startsWith("172.31.")
                || ip.equals("127.0.0.1")   || ip.startsWith("169.254.");
    }

}
