package com.manager.Zombie_Keeper.service.localNetwork.fingerprint;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.springframework.boot.system.ApplicationHome;
import org.springframework.stereotype.Service;


@Service
public class LocalNetworkFingerprintService {
    
    private String extractJson(String rawOutput){
        if (rawOutput == null || rawOutput.isEmpty()) {
            return "{}"; 
        }

        
        int startIndex = rawOutput.indexOf("{");
        int endIndex = rawOutput.lastIndexOf("}");

        
        if (startIndex != -1 && endIndex != -1 && endIndex > startIndex) {
            return rawOutput.substring(startIndex, endIndex + 1);
        }

        
        return rawOutput.startsWith("ERRO") ? rawOutput : "{}]";
    }

    

    public File getRootPath(){
        File currentDir = new File(System.getProperty("user.dir"));

        File modulesFolder = new File(currentDir, "modules");

        if (modulesFolder.exists() && modulesFolder.isDirectory()) {
         
            return currentDir;
        }

      return new ApplicationHome(getClass()).getDir();
        
    }

    public String excLocalNodeFingerPrint(String binaryName,String id, String mac, String networkIdentfier,  String flag, String sec, String usec ){

        List<String> comand = new ArrayList<>();
        StringBuilder output = new StringBuilder();

        try {
            
            File root = getRootPath();
            File binaryFile = new File(root, "modules/linux/c++/code/localFingerPrint/" + binaryName);


            if(!binaryFile.exists()){

                return "ERROR fileNotFound " + binaryFile.getAbsolutePath();
            }

            if(!binaryFile.canExecute()){
                binaryFile.setExecutable(true);
            }

            //Continue 

        } catch (Exception e) {
            // TODO: handle exception
        }

        return " ";
    }

    // "./Binary --create_session '-all-ports' or 'any-ports' "
    public String excLocalNetFingerPrint(String binaryName, String flag, String sec, String usec){

        List<String> command = new ArrayList<>();
        
        StringBuilder output = new StringBuilder();

        try {
            
            File root = getRootPath();     
            //Path for binary     
            File binaryFile = new File(root, "modules/linux/c++/code/localFingerPrint/" + binaryName );

            if(!binaryFile.exists()){

                return "ERROR fileNotFound " + binaryFile.getAbsolutePath();

            }

            if(!binaryFile.canExecute()){
                binaryFile.setExecutable(true);
            }

            command.add(binaryFile.getAbsolutePath());

            if(flag.equalsIgnoreCase("all")) {
                command.add("--create_session");
                command.add("-all-ports");
            } else if(flag.equalsIgnoreCase("any")) {
                command.add("--create_session");
                command.add("-any-ports");
            }

            command.add(sec);
            command.add(usec);
            
        } catch (Exception e) {
            
            System.out.println(e.getMessage());
        }

        try {

            ProcessBuilder pb = new ProcessBuilder(command);

            pb.redirectErrorStream(true);


            Process process = pb.start();
            

            try (BufferedReader buffer = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                
                String line;

                while ((line = buffer.readLine())  != null) {

                    output.append(line).append("\n");
                }
            } 

            boolean finished = process.waitFor(60, TimeUnit.SECONDS);

            if(!finished){
                process.destroyForcibly();
                output.append("\nERROR");
            }
            
        } catch (Exception e) {

            e.printStackTrace();

            System.out.println("Catch ERROR " +  e.getMessage());

        }


        return extractJson(output.toString()) ;
    }
}
