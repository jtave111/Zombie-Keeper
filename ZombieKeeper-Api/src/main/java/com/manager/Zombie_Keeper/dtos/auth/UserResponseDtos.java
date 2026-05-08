package com.manager.Zombie_Keeper.dtos.auth;

import com.manager.Zombie_Keeper.model.entity.auth.User;

public class UserResponseDtos {

    private Long   id;
    private String username;
    private String name;
    private String role;

    public UserResponseDtos(User user) {
        this.id       = user.getId();
        this.username = user.getUsername();
        this.name     = user.getName();
        this.role     = user.getRole() != null ? user.getRole().getName() : null;
    }

    public Long   getId()       { return id; }
    public String getUsername() { return username; }
    public String getName()     { return name; }
    public String getRole()     { return role; }
}
