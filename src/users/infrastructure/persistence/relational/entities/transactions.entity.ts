import { Column, Entity, ManyToOne, PrimaryGeneratedColumn } from "typeorm";
import { UserEntity } from "./user.entity";
import { ApiProperty } from "@nestjs/swagger";
import { EntityRelationalHelper } from "../../../../../utils/relational-entity-helper";


export enum Transactiontype{
    FUNDING ='funding',
    WITHDRAWAL ='withdrawal'
}

export enum TransactionStatus{
    SUCCESS ='success',
    FAILED ='failed',
    PENDING ='pending'
}


@Entity({name:"Transactions"})
export class TransactionEntity extends EntityRelationalHelper{

    @ApiProperty({type:Number})
    @PrimaryGeneratedColumn()
    id:number

    @ApiProperty({type:String})
    @Column({nullable:true})
    transactionID:string

    @ApiProperty({enum:Transactiontype})
    @Column({type:'enum',enum:TransactionStatus,nullable:true})
    type:Transactiontype

    @ApiProperty({enum:TransactionStatus})
    @Column({type:'enum',enum:TransactionStatus ,nullable:true})
    status:TransactionStatus

    @ApiProperty({type:Number})
    @Column('numeric',{nullable:true})
    amount:number

    @ApiProperty()
    @Column({type:'timestamp', nullable:true})
    transactedAT:Date

    @ApiProperty({ type: () => UserEntity })
    @ManyToOne(() => UserEntity, (user) => user.my_transactions, {onDelete:'CASCADE'})
    user:UserEntity

}