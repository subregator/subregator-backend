FROM python:3.12-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64 AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libffi-dev \
    && python -m venv /opt/irrd \
    && /opt/irrd/bin/pip install --no-cache-dir irrd==4.5.5

FROM python:3.12-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates gnupg libpq5 \
    && useradd --uid 10001 --create-home irrd \
    && install -d -o irrd -g irrd /var/lib/irrd/tmp /var/lib/irrd/gnupg /run/irrd
COPY --from=build /opt/irrd /opt/irrd
ENV PATH="/opt/irrd/bin:$PATH" TMPDIR=/var/lib/irrd/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
CMD ["irrd", "--config=/etc/irrd.yaml", "--foreground"]
