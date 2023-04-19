FROM python:3.11-slim as python-base
# Install updates and required software
RUN ["apt", "-y", "update"]

# Configure Poetry
FROM python-base as poetry-base
ENV POETRY_VERSION=1.4.1
ENV POETRY_HOME=/poetry
ENV POETRY_VENV=/poetry-venv
ENV POETRY_CACHE_DIR=/var/.cache
RUN python -m venv ${POETRY_VENV}
RUN ${POETRY_VENV}/bin/pip install -u pip setuptools
RUN ${POETRY_VENV}/bin/pip install poetry==${POETRY_VERSION}

# Configure the environment for py-crawler
FROM poetry-base as py-crawler-base
RUN ["apt", "-y", "install", "openjdk-17-jre-headless"]
COPY py-crawler /py-crawler
COPY secrets /py-crawler/secrets

# COPY poetry to app image and set path
COPY --from=poetry-base ${POETRY_VENV} ${POETRY_VENV}
ENV PATH="${PATH}:${POETRY_VENV}/bin"

WORKDIR /py-crawler

# Check configuration
RUN poetry check

# Install project dependencies
RUN poetry install --no-interaction -no-cache

ENV PLAYBOOKS_DIR="/playbooks"
ENV OUTPUT_DIR="/output"

CMD [ "python", "-m", "certreport", "/certs" ]