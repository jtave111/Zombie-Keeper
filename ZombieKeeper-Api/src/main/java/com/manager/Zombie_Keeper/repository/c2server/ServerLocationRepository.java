package com.manager.Zombie_Keeper.repository.c2server;

import com.manager.Zombie_Keeper.model.entity.c2Server.ServerLocation;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ServerLocationRepository extends JpaRepository<ServerLocation, Long> {

    List<ServerLocation> findByServerId(Long serverId);
}
