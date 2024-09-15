import { ApiProperty } from '@nestjs/swagger';
import { User } from '../../users/domain/user';
import { UserEntity } from '../../users/infrastructure/persistence/relational/entities/user.entity';

export class LoginResponseDto {
  @ApiProperty()
  token: string;

  @ApiProperty()
  refreshToken: string;

  @ApiProperty()
  tokenExpires: number;

  @ApiProperty({
    type: () => UserEntity,
  })
  user: UserEntity;
}
