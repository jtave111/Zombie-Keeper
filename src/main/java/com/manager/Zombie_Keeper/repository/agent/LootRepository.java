package com.manager.Zombie_Keeper.repository.agent;

import org.springframework.data.jpa.repository.JpaRepository;

import com.manager.Zombie_Keeper.model.entity.agent.Loot;

import java.util.UUID;

public interface LootRepository extends JpaRepository<Loot, UUID> {

}
