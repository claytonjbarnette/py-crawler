FROM python:3.11-slim as python-base
# Install updates and required software

# Configure Poetry
FROM python-base as poetry-base
ENV POETRY_VERSION=1.4.1
ENV POETRY_HOME=/poetry
ENV POETRY_VENV=/poetry-venv
ENV POETRY_CACHE_DIR=/var/.cache
RUN python -m venv ${POETRY_VENV}
RUN ${POETRY_VENV}/bin/pip install --upgrade pip setuptools
RUN ${POETRY_VENV}/bin/pip install poetry==${POETRY_VERSION}

# Configure the environment for py-crawler
FROM poetry-base as py-crawler-base
RUN ["apt", "-y", "update"]
RUN ["apt", "-y", "install", "openjdk-17-jre-headless"]
RUN ["apt", "-y", "install", "git"]
RUN ["apt", "-y", "install", "curl"]
RUN ["export", "ARCH=`dpkg --print-architecture`"]
RUN ["curl", "-Lo", "gh.tgz", "https://github.com/cli/cli/releases/download/v2.27.0/gh_2.27.0_linux_$ARCH.deb"]
RUN ["tar" "-tvf" "gh.tgz" "--strip-components=2"  "-C" "/usr/bin" "gh_2.27.0_linux_$ARCH/bin/gh"]

COPY py-crawler /py-crawler
COPY secrets /py-crawler/secrets

# COPY poetry to app image and set path
COPY --from=poetry-base ${POETRY_VENV} ${POETRY_VENV}
ENV PATH="${PATH}:${POETRY_VENV}/bin"

WORKDIR /py-crawler

# Check configuration
RUN poetry check

# Install project dependencies
RUN poetry install --no-interaction --no-cache

ENV PLAYBOOKS_DIR="/playbooks"
ENV OUTPUT_DIR="/output"

CMD [ "sh", "/py_crawler/fpki-graph-updates.sh" ]