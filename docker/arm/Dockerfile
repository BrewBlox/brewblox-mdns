FROM brewblox/brewblox-service:rpi-latest as base

COPY ./dist /build/dist

RUN pip3 install wheel \
    && pip3 wheel /build/dist/* --wheel-dir=/wheeley --find-links=/wheeley

FROM brewblox/rpi-python:3.7-slim
EXPOSE 9010
WORKDIR /app

COPY --from=base /wheeley /wheeley
COPY ./config /app/config

RUN ls /wheeley \
    && pip3 install --no-index --find-links=/wheeley brewblox-mdns \
    && rm -rf /wheeley \
    && pip3 freeze

ENTRYPOINT ["python3", "-m", "brewblox_mdns"]
