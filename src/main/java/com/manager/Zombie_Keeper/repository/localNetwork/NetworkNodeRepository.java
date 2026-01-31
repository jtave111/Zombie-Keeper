package com.manager.Zombie_Keeper.repository.localNetwork;

import org.springframework.data.jpa.repository.JpaRepository;

import com.manager.Zombie_Keeper.model.entity.localNetwork.NetworkNode;

public interface NetworkNodeRepository extends JpaRepository <NetworkNode, Long> {
    
    
}
