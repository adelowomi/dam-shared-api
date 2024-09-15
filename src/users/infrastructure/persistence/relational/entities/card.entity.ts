import { Column, Entity, ManyToOne, PrimaryGeneratedColumn } from "typeorm";
import { UserEntity } from "./user.entity";
import { ApiProperty } from "@nestjs/swagger";
import { EntityRelationalHelper } from "../../../../../utils/relational-entity-helper";





@Entity({name:"Card"})
export class CardEntity extends EntityRelationalHelper{

    @ApiProperty({type:Number})
    @PrimaryGeneratedColumn()
    id:number

    @ApiProperty({type:String})
    @Column({nullable:true})
    token:string

    @ApiProperty({type:String})
    @Column({nullable:true})
    cardType:string

    @ApiProperty({type:String})
    @Column({nullable:true})
    last4Digits :string

    @ApiProperty({type:String})
    @Column({ nullable:true})
    expiryMonth:string

    @ApiProperty({type:String})
    @Column({ nullable:true})
    expiryYear:string

    @ApiProperty()
    @Column({ type: 'timestamp' , nullable:true})
    addedAt: Date;
  
    @ApiProperty()
    @Column({ type: 'timestamp', nullable:true })
    deletedAt: Date;


    @ApiProperty({ type: () => UserEntity })
    @ManyToOne(() => UserEntity, (user) => user.my_cards, {onDelete:'CASCADE'})
    user:UserEntity

}