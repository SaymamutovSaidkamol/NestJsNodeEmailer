import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class UpdateProductDto {
  @ApiProperty({ example: 'Samsung' })
  @IsString()
  name: string;

  @ApiProperty({ example: 'Black' })
  @IsString()
  color: string;

  @ApiProperty({ example: '75a5bc0b-5755-49fc-9a52-cf04a2b01661' })
  @IsString()
  categoryId: string;
}
