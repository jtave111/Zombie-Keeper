package com.manager.Zombie_Keeper.repository.c2server;

import com.manager.Zombie_Keeper.model.entity.c2Server.DatabaseConfig;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface DatabaseConfigRepository extends JpaRepository<DatabaseConfig, Long> {

    List<DatabaseConfig> findByServerId(Long serverId);
}
