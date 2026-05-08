import Fastify from 'fastify';
const app = Fastify();
app.get('/', async () => 'hi');
app.listen({ port: 3000 });
