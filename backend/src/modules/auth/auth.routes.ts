import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import otpGenerator from 'otp-generator';
import { z } from 'zod';

const prisma = new PrismaClient();

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  countryCode: z.string().length(2),
});

const verifyEmailSchema = z.object({
  email: z.string().email(),
  otpCode: z.string().length(6),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

export async function registerRoutes(app: FastifyInstance) {
  app.post('/auth/register', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const body = registerSchema.parse(request.body);
      
      const existingUser = await prisma.user.findUnique({
        where: { email: body.email },
      });
      
      if (existingUser) {
        return reply.status(409).send({ error: 'Email déjà utilisé' });
      }
      
      const passwordHash = await argon2.hash(body.password, {
        type: argon2.argon2id,
        memoryCost: 65536,
        timeCost: 3,
        parallelism: 4,
      });
      
      const user = await prisma.user.create({
        data: {
          email: body.email,
          passwordHash,
          countryCode: body.countryCode,
          kycLevel: 0,
        },
      });
      
      const otpCode = otpGenerator.generate(6, {
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false,
        specialChars: false,
      });
      
      await prisma.otpCode.create({
        data: {
          userId: user.id,
          type: 'email_verification',
          code: otpCode,
          channel: 'email',
          expiresAt: new Date(Date.now() + 10 * 60 * 1000),
        },
      });
      
      await prisma.securityEvent.create({
        data: {
          userId: user.id,
          eventType: 'user_registered',
          severity: 'info',
          details: { email: body.email },
        },
      });
      
      return reply.status(201).send({
        message: 'Compte créé. Vérifiez votre email.',
        userId: user.id,
        otpCode: otpCode,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return reply.status(400).send({ error: 'Données invalides', details: error.errors });
      }
      console.error('Register error:', error);
      return reply.status(500).send({ error: 'Erreur serveur' });
    }
  });
  
  app.post('/auth/verify-email', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const body = verifyEmailSchema.parse(request.body);
      
      const user = await prisma.user.findUnique({
        where: { email: body.email },
      });
      
      if (!user) {
        return reply.status(404).send({ error: 'Utilisateur non trouvé' });
      }
      
      const otp = await prisma.otpCode.findFirst({
        where: {
          userId: user.id,
          type: 'email_verification',
          code: body.otpCode,
          used: false,
          expiresAt: { gt: new Date() },
        },
        orderBy: { createdAt: 'desc' },
      });
      
      if (!otp) {
        return reply.status(400).send({ error: 'Code invalide ou expiré' });
      }
      
      await prisma.otpCode.update({
        where: { id: otp.id },
        data: { used: true, usedAt: new Date() },
      });
      
      await prisma.user.update({
        where: { id: user.id },
        data: { kycLevel: 1 },
      });
      
      await prisma.kycHistory.create({
        data: {
          userId: user.id,
          previousLevel: 0,
          newLevel: 1,
          reason: 'Email vérifié',
        },
      });
      
      const accessToken = jwt.sign(
        { userId: user.id, kycLevel: 1 },
        process.env.JWT_SECRET!,
        { expiresIn: '15m' }
      );
      
      const refreshToken = jwt.sign(
        { userId: user.id },
        process.env.JWT_REFRESH_SECRET!,
        { expiresIn: '7d' }
      );
      
      await prisma.session.create({
        data: {
          userId: user.id,
          tokenHash: await argon2.hash(accessToken),
          refreshTokenHash: await argon2.hash(refreshToken),
          expiresAt: new Date(Date.now() + 15 * 60 * 1000),
          refreshExpiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        },
      });
      
      await prisma.securityEvent.create({
        data: {
          userId: user.id,
          eventType: 'email_verified',
          severity: 'info',
          details: { kycLevel: 1 },
        },
      });
      
      return reply.send({
        message: 'Email vérifié avec succès',
        tokens: { accessToken, refreshToken },
        user: { id: user.id, kycLevel: 1 },
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return reply.status(400).send({ error: 'Données invalides' });
      }
      console.error('Verify email error:', error);
      return reply.status(500).send({ error: 'Erreur serveur' });
    }
  });
  
  app.post('/auth/login', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const body = loginSchema.parse(request.body);
      
      const user = await prisma.user.findUnique({
        where: { email: body.email },
      });
      
      if (!user) {
        await prisma.loginAttempt.create({
          data: {
            email: body.email,
            success: false,
            failureReason: 'user_not_found',
          },
        });
        return reply.status(401).send({ error: 'Email ou mot de passe incorrect' });
      }
      
      const validPassword = await argon2.verify(user.passwordHash, body.password);
      
      if (!validPassword) {
        await prisma.loginAttempt.create({
          data: {
            email: body.email,
            success: false,
            failureReason: 'wrong_password',
          },
        });
        return reply.status(401).send({ error: 'Email ou mot de passe incorrect' });
      }
      
      if (user.kycLevel < 1) {
        return reply.status(403).send({ error: 'Vérifiez votre email d\'abord' });
      }
      
      const accessToken = jwt.sign(
        { userId: user.id, kycLevel: user.kycLevel },
        process.env.JWT_SECRET!,
        { expiresIn: '15m' }
      );
      
      const refreshToken = jwt.sign(
        { userId: user.id },
        process.env.JWT_REFRESH_SECRET!,
        { expiresIn: '7d' }
      );
      
      await prisma.session.create({
        data: {
          userId: user.id,
          tokenHash: await argon2.hash(accessToken),
          refreshTokenHash: await argon2.hash(refreshToken),
          expiresAt: new Date(Date.now() + 15 * 60 * 1000),
          refreshExpiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        },
      });
      
      await prisma.loginAttempt.create({
        data: {
          email: body.email,
          success: true,
        },
      });
      
      await prisma.securityEvent.create({
        data: {
          userId: user.id,
          eventType: 'user_login',
          severity: 'info',
        },
      });
      
      await prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
      });
      
      return reply.send({
        message: 'Connexion réussie',
        tokens: { accessToken, refreshToken },
        user: { id: user.id, email: user.email, kycLevel: user.kycLevel },
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return reply.status(400).send({ error: 'Données invalides' });
      }
      console.error('Login error:', error);
      return reply.status(500).send({ error: 'Erreur serveur' });
    }
  });
}
