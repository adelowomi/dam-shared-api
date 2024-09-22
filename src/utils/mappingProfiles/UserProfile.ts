import { AutomapperProfile, InjectMapper } from '@automapper/nestjs';
import { Injectable } from '@nestjs/common';
import {
  createMap,
  forMember,
  mapFrom,
  type Mapper,
  type MappingProfile,
} from '@automapper/core';
import { UserEntity } from '../../users/infrastructure/persistence/relational/entities/user.entity';
import { UserView } from '../../users/dto/view-dtos/user-view';

@Injectable()
export class UserProfile extends AutomapperProfile {
  constructor(@InjectMapper() mapper: Mapper) {
    super(mapper);
  }

  get profile(): MappingProfile {
    return (mapper) => {
      createMap(
        mapper,
        UserEntity,
        UserView,
        forMember(
          (destination) => destination.id,
          mapFrom((source) => source.id),
        ),
        forMember(
          (destination) => destination.email,
          mapFrom((source) => source.email),
        ),
        forMember(
          (destination) => destination.title,
          mapFrom((source) => source.title),
        ),
        forMember(
          (destination) => destination.middleName,
          mapFrom((source) => source.middleName),
        ),
        forMember(
          (destination) => destination.firstName,
          mapFrom((source) => source.firstName),
        ),
        forMember(
          (destination) => destination.lastName,
          mapFrom((source) => source.lastName),
        ),
        forMember(
          (destination) => destination.DOB,
          mapFrom((source) => source.DOB),
        ),
        forMember(
          (destination) => destination.age,
          mapFrom((source) => source.age),
        ),
        forMember(
          (destination) => destination.gender,
          mapFrom((source) => source.gender),
        ),
      );
    };
  }

  //   protected get mappingConfigurations(): MappingConfiguration[] {
  //     // the 3 createMap() above will get this `extend()`
  //     return [extend(BaseEntity, BaseDto)];
  //   }
}
