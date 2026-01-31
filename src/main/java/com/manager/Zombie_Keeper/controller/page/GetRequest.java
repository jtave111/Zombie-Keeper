package com.manager.Zombie_Keeper.controller.page;

import java.nio.file.AccessDeniedException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import com.manager.Zombie_Keeper.model.entity.auth.User;


@Controller
public class GetRequest {
    
    @GetMapping("/")
    public String getHome(){
        return "home";
    }
    
    @GetMapping("/agents")
    public String getAgents(){

        return "agents";
    }

    @GetMapping("/login")
    public String getLogin(){
        
        return "login";
    }

    @GetMapping("/register")
    public String getRegister() throws AccessDeniedException {
            
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        
        // Neste projeto o principal é a entidade User (auth manual)
        User user = (User) auth.getPrincipal();

        if(!"ADMIN".equals(user.getRole().getType())){


            throw new AccessDeniedException("Forbidden");

        }
        
        return "register";
    }
    
}


