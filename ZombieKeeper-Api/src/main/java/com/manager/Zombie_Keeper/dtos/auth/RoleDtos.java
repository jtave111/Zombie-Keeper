package com.manager.Zombie_Keeper.dtos.auth;

import jakarta.validation.constraints.NotBlank;

public class RoleDtos {
    @NotBlank(message = "not balank field")
    private String name;


    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
