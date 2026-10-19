import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import { registerRoutes } from './modules/auth/auth.routes';

const app = Fastify({ logger: true });

app.register(helmet);
app.register(cors, { origin: true });

app.register(registerRoutes);

app.get('/health', async () => {
  return { status: 'ok', timestamp: new Date().toISOString() };
});

const start = async () => {
  try {
    const port = Number(process.env.PORT) || 3000;
    await app.listen({ port, host: '0.0.0.0' });
    console.log(`Serveur démarré sur le port ${port}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

start();
