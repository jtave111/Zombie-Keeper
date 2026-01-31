package com.manager.Zombie_Keeper.repository.auth;


import org.springframework.data.jpa.repository.JpaRepository;

import com.manager.Zombie_Keeper.model.entity.auth.Role;

public interface RoleRepository extends JpaRepository<Role, Long> {
    
    Role findByType(String type);
   
}
