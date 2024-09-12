import { Injectable } from "@nestjs/common";
import { Repository } from "typeorm";
import { NotificationsEntity } from "../users/infrastructure/persistence/relational/entities/notifications.entity";
import { CreateNotificationsDto } from "../utils/dto/notifications.dto";
import { InjectRepository } from "@nestjs/typeorm";

@Injectable()
export class NotificationsService{
    constructor(@InjectRepository(NotificationsEntity) private readonly notificationsRepository: Repository<NotificationsEntity>){}

    async create(dto:CreateNotificationsDto):Promise<NotificationsEntity>{
        return await this.notificationsRepository.create({
            message:dto.message,
            subject:dto.message,
            account:dto.account,
            isRead:false,
        })
    }
}