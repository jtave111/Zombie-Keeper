package com.manager.Zombie_Keeper.service.processManagerService;

import java.util.Map;

import org.springframework.stereotype.Service;

@Service
public class ProcessManagerService {

    public boolean killProcess(String processName, Map<String, Process> activeProcess){

        Process p = activeProcess.get(processName);

        if(p != null && p.isAlive()){
            p.destroyForcibly();

            return true;
        }
        return false;
    }

}
