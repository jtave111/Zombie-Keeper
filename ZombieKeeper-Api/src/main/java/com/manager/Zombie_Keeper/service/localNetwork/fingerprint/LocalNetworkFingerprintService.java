package com.manager.Zombie_Keeper.service.localNetwork.fingerprint;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import org.springframework.boot.system.ApplicationHome;
import org.springframework.stereotype.Service;

import com.manager.Zombie_Keeper.model.entity.localNetwork.NetworkSession;

import tools.jackson.databind.ObjectMapper;


@Service
public class LocalNetworkFingerprintService {

    private final Map<String, Process> activeProcesses = new ConcurrentHashMap<>();


    public Map<String, Process> getActiveProcesses(){
        
        return this.activeProcesses;
    }

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


    //TODO: implementar sobrescritas dos metodos 
    public NetworkSession localNetworkFingerprint(Consumer<String> onProgress, String binaryName, String flag, String sec, String usec){
        
        NetworkSession session = new NetworkSession();

        List<String> command = new ArrayList<>();

        StringBuilder builder =  new StringBuilder();


        try {
            
            File root = getRootPath();

            File binaryFile = new File(root, "modules/linux/c++/code/localFingerPrint/" + binaryName );

            if(!binaryFile.exists() ) throw new FileNotFoundException();

            if(!binaryFile.canExecute()) binaryFile.setExecutable(true);


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

            ProcessBuilder pb = new ProcessBuilder(command);

            pb.redirectErrorStream(true);

            Process process = pb.start();


            boolean isParsingJson = false;
            try(
                BufferedReader buffer = new BufferedReader(new InputStreamReader(process.getInputStream()));

            ) {
                
                String line;
                //TODO: implementar isso no bonario(c++)
                //Possivel logica 
                while ((line = buffer.readLine()) != null) {
                    
                    if (line.trim().equals("[ZK_JSON_START]")) {
                        isParsingJson = true;
                        continue; 
                    }

                    if (isParsingJson) {
                        
                        builder.append(line).append("\n");
                    } else {
                        onProgress.accept(line);
                    }
                }


            } catch (Exception e) {
            
            }


            String outputJson = extractJson(builder.toString());

            if (outputJson.length() > 0) {
                ObjectMapper mapper = new ObjectMapper();
                
                session = mapper.readValue(outputJson.toString(), NetworkSession.class);
            } else {
                onProgress.accept("[ERRO] Nenhum dado JSON retornado ");
            }

        } catch (Exception e) {
            
        }
        return  session;
    }


    //C++ binaries 
    public String excLocalNodeFingerPrint(String binaryName,  String mac, String networkIdentfier,  String flag, String sec, String usec ){

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

            comand.add(binaryFile.getAbsolutePath());
            
            comand.add("--scan_node");
            comand.add(mac);
            comand.add(networkIdentfier);
            comand.add(flag);
            comand.add(sec);
            comand.add(usec);



        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        try {

            ProcessBuilder pb = new ProcessBuilder(comand);

            pb.redirectErrorStream(true);

            Process process = pb.start();

            try(BufferedReader buffer = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                
                String line;

                while ((line = buffer.readLine()) != null) {
                    output.append(line).append("\n");
                }



            } catch (Exception e) {
                System.out.println("ERROR " + e.getMessage());
            }

            boolean finished  = process.waitFor(60, TimeUnit.SECONDS);
            
            if(!finished) {
                process.destroyForcibly();
                output.append("\nERROR");
            }


            int exitCode = process.exitValue();

            if(exitCode == 1 ) return "falidPing";
            
        } catch (Exception e) {
           e.printStackTrace();
           System.out.println("ERROR " + e.getMessage());
        
        }

        return extractJson(output.toString());
    }

    public int excLocalPortScan(String binaryName, String networkIdentfier, String mac, String ip, String port, String sec, String usec){

        List<String> comand = new ArrayList<>();

        try {

            File root = this.getRootPath();
            File binaryFile = new File(root, "modules/linux/c++/code/localFingerPrint/" + binaryName );
            

            if(!binaryFile.exists()) throw new FileNotFoundException();

            if(!binaryFile.canExecute()){
                binaryFile.setExecutable(true);
            }
            
            comand.add(binaryFile.getAbsolutePath());
            comand.add("--simple_scan");
            comand.add(networkIdentfier);
            comand.add(mac);
            comand.add(ip);
            comand.add(port);
            comand.add(sec);
            comand.add(usec);
        
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("ERROR " + e.getMessage());
        }


        int exitCode =-1;
        try {
            
            ProcessBuilder pb = new ProcessBuilder(comand);
            Process process = pb.start();

            boolean finished = process.waitFor(60, TimeUnit.SECONDS);

            if(!finished){
                process.destroyForcibly();
                
            }

            exitCode = process.exitValue();


        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("ERROR " + e.getMessage());
        }

        return exitCode;

    }

    // "./Binary --create_session '-all-ports' or 'any-ports' "
    public String localNetFingerPrintToJson(String binaryName, String flag, String sec, String usec){

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


    //Python scripts 
    public String execRequestAutomation(String scriptName, String JSESSIONID, String URL ){

        if (activeProcesses.containsKey(scriptName)) {
            
            return "ALREADY_RUNNING";
        }

        List<String> command = new ArrayList<>();

        StringBuilder output = new StringBuilder();


        try {

            File root = getRootPath();
            File scriptFile = new File(root, "modules/python/localFingerPrint/requestAutomation/" + scriptName);

            if(!scriptFile.exists()) throw new FileNotFoundException();

            command.add("python3");
            command.add(scriptFile.getAbsolutePath());
            command.add(JSESSIONID);
            command.add(URL);

            
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            activeProcesses.put(scriptName, process);

            try(BufferedReader buffer = new BufferedReader(new InputStreamReader(process.getInputStream()))){
                String line;
                
                while ((line = buffer.readLine()) != null) {
                    
                    output.append(line).append("\n");
                    System.out.println(line);
                }
            }

            process.waitFor(); 
            activeProcesses.remove(scriptName);
   
        } catch (Exception e) {
            activeProcesses.remove(scriptName);
            e.printStackTrace();
            System.out.println("ERROR " + e.getMessage());
        
        }
        
        return output.toString();
    }
}
