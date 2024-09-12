import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserEntity } from './infrastructure/persistence/relational/entities/user.entity';
import { User } from './domain/user';
import { UserMapper } from './infrastructure/persistence/relational/mappers/user.mapper';
import { IPaginationOptions } from '../utils/types/pagination-options';
import { SortUserDto } from './dto/query-user.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
  ) {}

  async create(userData: Partial<User>): Promise<User> {
    const userEntity = UserMapper.toPersistence(userData as User);
    const savedEntity = await this.userRepository.save(userEntity);
    return UserMapper.toDomain(savedEntity);
  }

  async findManyWithPagination(options: {
    sortOptions?: SortUserDto[];
    paginationOptions: IPaginationOptions;
  }): Promise<User[]> {
    const { sortOptions, paginationOptions } = options;
    const query = this.userRepository.createQueryBuilder('user');

    if (sortOptions?.length) {
      sortOptions.forEach((sort) => {
        query.addOrderBy(`user.${sort.orderBy}`, sort.order);
      });
    }

    query
      .skip((paginationOptions.page - 1) * paginationOptions.limit)
      .take(paginationOptions.limit);

    const entities = await query.getMany();
    return entities.map(UserMapper.toDomain);
  }

  async findById(id: number): Promise<User> {
    const userEntity = await this.userRepository.findOne({ where: { id: id } });
    if (!userEntity) {
      throw new NotFoundException(`User with ID "${id}" not found`);
    }
    return UserMapper.toDomain(userEntity);
  }

  async findByEmail(email: string): Promise<User | null> {
    const userEntity = await this.userRepository.findOne({
      where: { email: email },
    });
    return userEntity ? UserMapper.toDomain(userEntity) : null;
  }

  async update(id: number, updateData: Partial<User>): Promise<User> {
    const existingUser = await this.findById(id);
    const updatedUser = { ...existingUser, ...updateData };
    const updatedEntity = await this.userRepository.save(
      UserMapper.toPersistence(updatedUser),
    );
    return UserMapper.toDomain(updatedEntity);
  }

  async remove(id: number): Promise<void> {
    const result = await this.userRepository.softDelete(id);
    if (result.affected === 0) {
      throw new NotFoundException(`User with ID "${id}" not found`);
    }
  }
}
