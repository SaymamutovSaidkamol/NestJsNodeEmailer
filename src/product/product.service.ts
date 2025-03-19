import {
  BadRequestException,
  Injectable,
  NotFoundException,
  Req,
} from '@nestjs/common';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { Request } from 'express';

@Injectable()
export class ProductService {
  constructor(private prisma: PrismaService) {}

  async create(data: CreateProductDto) {
    let newCateg = await this.prisma.product.createMany({ data });

    return { data: newCateg };
  }

  async findAll() {
    let all = await this.prisma.product.findMany({
      include: { category: true },
    });
    return { data: all };
  }

  async findOne(id: string) {
    let OneCateg = await this.prisma.product.findFirst({
      where: { id },
      include: { category: true },
    });

    if (!OneCateg) {
      throw new NotFoundException('product Not Found');
    }

    return { data: OneCateg };
  }

  async update(id: string, data: UpdateProductDto, @Req() req: Request) {
    if (req['user'].id !== id) {
      throw new BadRequestException(
        'You cannot change your information for someone else.',
      );
    }

    let OneCateg = await this.prisma.product.findFirst({ where: { id } });

    if (!OneCateg) {
      throw new NotFoundException('product Not Found');
    }

    let updateCateg = await this.prisma.product.updateMany({
      where: { id },
      data,
    });

    return { data: updateCateg };
  }

  async remove(id: string, @Req() req: Request) {
    if (req['user'].id !== id) {
      throw new BadRequestException(
        'You cannot change your information for someone else.',
      );
    }

    let OneCateg = await this.prisma.product.findFirst({ where: { id } });

    if (!OneCateg) {
      throw new NotFoundException('product Not Found');
    }

    let del = await this.prisma.product.delete({ where: { id } });

    return { data: del };
  }
}
