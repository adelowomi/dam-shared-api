import { plainToClass } from 'class-transformer';
import { FileMapper } from '../../../../../files/infrastructure/persistence/relational/mappers/file.mapper';
import { User } from '../../../../domain/user';
import { UserEntity } from '../entities/user.entity';

export class UserMapper {
  static toDomain(raw: UserEntity): User {
    return plainToClass(User, {
      ...raw,
      photo: raw.photo ? FileMapper.toDomain(raw.photo) : null,
    }, { excludeExtraneousValues: true });
  }

  static toPersistence(domainEntity: User): UserEntity {
    const persistenceEntity = new UserEntity();
    Object.assign(persistenceEntity, domainEntity);

    if (domainEntity.photo) {
      persistenceEntity.photo = FileMapper.toPersistence(domainEntity.photo);
    }

    return persistenceEntity;
  }
}