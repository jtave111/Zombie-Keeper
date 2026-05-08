package com.manager.Zombie_Keeper.dtos.auth;

import jakarta.validation.constraints.NotBlank;

public class UserDtos {

   @NotBlank(message = "not balank field")
   private String name;
   @NotBlank(message = "not balank field")
   private String username;
   @NotBlank(message = "not balank field")
   private String password;

   @NotBlank(message = "not balank field")
   private RoleDtos role;



   public String getName() {
    return name;
   }
   public void setName(String name) {
    this.name = name;
   }
   public String getUsername() {
    return username;
   }
   public void setUsername(String username) {
    this.username = username;
   }
   public String getPassword() {
    return password;
   }
   public void setPassword(String password) {
    this.password = password;
   }
   public RoleDtos getRole() {
    return role;
   }
   public void setRole(RoleDtos role) {
    this.role = role;
   }


}

