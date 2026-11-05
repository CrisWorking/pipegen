const fastify = require('fastify')();
fastify.get('/ping', async () => 'pong');
fastify.listen({ port: Number(process.env.PORT || 4000) });
