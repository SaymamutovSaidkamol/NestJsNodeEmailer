import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateCategoryDto } from './dto/create-category.dto';
import { UpdateCategoryDto } from './dto/update-category.dto';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class CategoryService {
  constructor(private prisma: PrismaService) {}

  async create(data: CreateCategoryDto) {
    let checkCateg = await this.prisma.category.findFirst({
      where: { name: data.name },
    });

    if (checkCateg) {
      throw new BadRequestException('This Category alredy exist');
    }

    let newCateg = await this.prisma.category.createMany({ data });

    return { data: newCateg };
  }

  async findAll() {
    let all = await this.prisma.category.findMany();
    return { data: all };
  }

  async findOne(id: string) {
    let OneCateg = await this.prisma.category.findFirst({ where: { id } });

    if (!OneCateg) {
      throw new NotFoundException('Category Not Found');
    }

    return { data: OneCateg };
  }

  async update(id: string, data: UpdateCategoryDto) {
    let OneCateg = await this.prisma.category.findFirst({ where: { id } });

    if (!OneCateg) {
      throw new NotFoundException('Category Not Found');
    }

    let checkCateg = await this.prisma.category.findFirst({
      where: { name: data.name },
    });

    if (checkCateg) {
      throw new BadRequestException('This Category alredy exist');
    }

    let updateCateg = await this.prisma.category.updateMany({
      where: { id },
      data,
    });

    return { data: updateCateg };
  }

  async remove(id: string) {
    let OneCateg = await this.prisma.category.findFirst({ where: { id } });

    if (!OneCateg) {
      throw new NotFoundException('Category Not Found');
    }

    let del = await this.prisma.category.delete({ where: { id } });

    return { data: del };
  }
}
