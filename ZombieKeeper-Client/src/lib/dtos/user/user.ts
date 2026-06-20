export interface UserDto {
  id: number;
  username: string;
  name: string;
  role: string;
}

export interface CreateUserDto {
  username: string;
  name: string;
  password: string;
  roleName: string;

}

export interface RoleDto {
  id: number;
  name: string;
}

export interface LoginResponseDto {
  status: string;
  token: string;
  username: string;
  message: string;
}