import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, //remove unknown properties from DTOs
      forbidNonWhitelisted: false, //return error on unknown properties from DTOs
    }),
  );
  await app.listen(process.env.PORT ?? 3333);
}
bootstrap();
