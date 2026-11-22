# Two images from one file:
#   service  the Python service that watches Gmail (docker compose builds it with `target: service`)
#   relay    nginx, the only part reachable from outside (last stage, so a plain `docker build .` gives the relay)

FROM python:3.13-alpine AS service
RUN addgroup -S -g 10001 codes && adduser -S -D -H -u 10001 -G codes codes \
 && mkdir -p /app /data /run/codes /config && chown codes:codes /data /run/codes && chmod 700 /data \
 && printf '#!/bin/sh\nexec python3 -I /app/codes.py "$@"\n' > /usr/local/bin/codes && chmod 755 /usr/local/bin/codes
COPY server/*.py server/public_suffix_list.dat /app/
ENV CODES_CONFIG=/config/codes.env \
    CODES_STATE_DIR=/data \
    CODES_SOCKET=/run/codes/codes.sock \
    CODES_ALIASES_FILE=/config/aliases.json \
    PYTHONDONTWRITEBYTECODE=1
USER codes
ENTRYPOINT ["codes"]
CMD ["serve"]

FROM nginx:stable-alpine AS relay
COPY relay/nginx.conf /etc/nginx/conf.d/default.conf
COPY relay/test/ /usr/share/nginx/test/
EXPOSE 80
