package com.manager.Zombie_Keeper.service.properties;

import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.Properties;

@Service
public class PropertiesServices {

    public Properties getProperties(){

        try(InputStream input = PropertiesServices.class.getClassLoader()
                .getResourceAsStream("application.properties"))
        {

            Properties props = new Properties();

            props.load(input);

            return props;

        }catch (Exception e){
            throw new RuntimeException(e.getMessage());

        }
    }
}
