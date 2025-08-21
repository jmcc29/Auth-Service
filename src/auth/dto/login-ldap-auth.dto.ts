import { IsString, IsNotEmpty } from 'class-validator';

export class LoginLdapAuthDto {
    @IsString()
    @IsNotEmpty()
    username: string;

    @IsString()
    @IsNotEmpty()
    password: string;
}