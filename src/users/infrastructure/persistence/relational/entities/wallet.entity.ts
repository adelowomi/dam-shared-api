import {
  Column,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  OneToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { UserEntity } from './user.entity';
import { ApiProperty } from '@nestjs/swagger';

@Entity({ name: 'Wallet' })
export class WalletEntity {
  @ApiProperty({ type: String })
  @Index()
  @PrimaryGeneratedColumn('uuid')
  walletID: string;

  @ApiProperty({ type: Number })
  @Index()
  @Column('numeric', { nullable: true, default: 0.0 })
  balance: number;

  @ApiProperty()
  @Column({ nullable: true, type: 'timestamp' })
  createdAt: Date;

  @ApiProperty()
  @Column({ nullable: true, type: 'timestamp' })
  lastDepositAt: Date;

  @ApiProperty()
  @Column({ nullable: true, type: 'timestamp' })
  lastwithdrawalAt: Date;

  @ApiProperty({ type: () => UserEntity })
  @ManyToOne(() => UserEntity, (user) => user.my_wallet, {
    eager: true,
    onDelete: 'CASCADE',
  })
  owner: UserEntity;
}
