# CarBoys ARCA Server — imagen de producción (Railway)
FROM node:20-slim

# openssl: firma del ticket de acceso (CMS) para WSAA.
# ca-certificates: cadena de confianza para validar los certificados de AFIP.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencias exactas del lockfile, sin las de desarrollo.
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --chown=node:node server.js ./

# El servidor corre sin privilegios.
USER node

ENV NODE_ENV=production
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
