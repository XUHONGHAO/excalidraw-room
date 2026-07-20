ARG ROOM_NODE_IMAGE=node:20.19.4-alpine@sha256:df02558528d3d3d0d621f112e232611aecfee7cbc654f6b375765f72bb262799

FROM ${ROOM_NODE_IMAGE} AS build

WORKDIR /srv/excalidraw-room

COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile --network-timeout 600000

COPY tsconfig.json ./
COPY src ./src
RUN yarn build

FROM ${ROOM_NODE_IMAGE} AS runtime

ENV NODE_ENV=production
ENV PORT=8080

WORKDIR /srv/excalidraw-room

COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile --production --network-timeout 600000 \
  && yarn cache clean

COPY --from=build /srv/excalidraw-room/dist ./dist

USER node
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/readyz || exit 1

CMD ["node", "dist/index.js"]
