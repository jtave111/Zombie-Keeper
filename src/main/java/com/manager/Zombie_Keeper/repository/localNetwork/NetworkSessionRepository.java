package com.manager.Zombie_Keeper.repository.localNetwork;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.manager.Zombie_Keeper.model.entity.localNetwork.NetworkSession;

public interface NetworkSessionRepository extends JpaRepository<NetworkSession, UUID> {
    
    Optional<NetworkSession> findByNetworkIdentifier(String networkIdentifier);

    @Query("SELECT n.id FROM NetworkSession n WHERE n.networkIdentifier = :networkIdentifier")
    UUID findIdByNetworkIdentifier(String networkIdentifier);

}
