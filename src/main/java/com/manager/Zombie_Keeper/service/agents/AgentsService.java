package com.manager.Zombie_Keeper.service.agents;

import java.util.HashMap;
import java.util.HashSet;

import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Service;

import com.manager.Zombie_Keeper.model.entity.agent.Agent;
import com.manager.Zombie_Keeper.model.enums.agent.Tags;

@Service
public class AgentsService {
  


    public Agent setPreInformation(Agent agent){
        
        Set<Tags> tags = new HashSet<>();
        //Os tags 
        if(isWin(agent.getOs())){
            tags.add(Tags.WINDOWS);

        }else if(isLinux(agent.getOs())){
            tags.add(Tags.LINUX);

        }else if(isMac(agent.getOs())){

            tags.add(Tags.MAC);
        }
        


        agent.setTgas(tags);

        return agent;
    }



    public Boolean isWin(String os){
        
        if (!os.contains("w") || !os.contains("i") || !os.contains("n")) {
            return false;
        }

        if(os.length() < 3) return false;

        os = os.toLowerCase().replaceAll("\\s", "");

        if(os.equalsIgnoreCase("windows")) return true;

        int pointer = 0, i= 0 , target = 0;
        char []  expected = {'w', 'i', 'n' };

        while (pointer < 3) if(os.charAt(pointer++) == expected[ i++]) target++;

        if(target == 3) return true;


        char[] arr = {'w', 'i', 'n', 'd',  'o', 'n', 'w', };

        Map<Integer, Boolean> map = new HashMap<>();

        int acept = 6, contArr = 0, aux = 0;

        for(int j = 0; j < os.length(); j ++){


            map.put(contArr, false);

            if(os.charAt(j) == arr[contArr] && (map.get(contArr) == false ) ){

                map.put(contArr, true);

                aux ++;

            }

            contArr ++;

            if(contArr >=  arr.length ) contArr = 0;

        }

        if(aux == acept -1) return true;

        return  false;
    }

    public Boolean isLinux(String os) {
        os = os.toLowerCase().replaceAll("\\s", "");
        
        if (os.length() < 3) return false;

        if (!os.contains("l") || !os.contains("i") || !os.contains("n")) {
            return false;
        }

        if (os.contains("linux")) return true;

        int pointer = 0, i = 0, target = 0;
        char[] expected = {'l', 'i', 'n'}; 

        while (pointer < 3 && pointer < os.length()) {
            if (os.charAt(pointer++) == expected[i++]) target++;
        }
        
        if (target == 3) return true;

        char[] arr = {'l', 'i', 'n', 'u', 'x'};
        Map<Integer, Boolean> map = new HashMap<>();
        int acept = 4, contArr = 0, aux = 0;

        for (int j = 0; j < os.length(); j++) {
            map.put(contArr, false);
            if (os.charAt(j) == arr[contArr] && !map.get(contArr)) {
                map.put(contArr, true);
                aux++;
            }
            contArr++;
            if (contArr >= arr.length) contArr = 0;
        }

        return aux >= acept;
    }
 

    public Boolean isMac(String os) {
        os = os.toLowerCase().replaceAll("\\s", "");
        
        if (os.length() < 3) return false;

        if (!os.contains("m") || !os.contains("a") || !os.contains("c")) {
            return false;
        }

        if (os.contains("macos") || os.contains("darwin")) return true;

        int pointer = 0, i = 0, target = 0;
        char[] expected = {'m', 'a', 'c'};

        while (pointer < 3 && pointer < os.length()) {
            if (os.charAt(pointer++) == expected[i++]) target++;
        }
        
        if (target == 3) return true;

        char[] arr = {'m', 'a', 'c', 'o', 's'};
        Map<Integer, Boolean> map = new HashMap<>();
        int acept = 3, contArr = 0, aux = 0;

        for (int j = 0; j < os.length(); j++) {
            map.put(contArr, false);
            if (os.charAt(j) == arr[contArr] && !map.get(contArr)) {
                map.put(contArr, true);
                aux++;
            }
            contArr++;
            if (contArr >= arr.length) contArr = 0;
        }

        return aux >= acept;
    }


}
