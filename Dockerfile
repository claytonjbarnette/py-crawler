FROM python:3.11-slim as python-base

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
# COPY poetry to app image and set path
COPY --from=poetry-base ${POETRY_VENV} ${POETRY_VENV}
ENV PATH="${PATH}:${POETRY_VENV}/bin"
# Install updates and required software
RUN ["apt", "-y", "update"]
# Install the JRE
RUN ["apt", "-y", "install", "openjdk-17-jre-headless"]
# Install GI
RUN ["apt", "-y", "install", "git"]
# Install curl
RUN ["apt", "-y", "install", "curl"]
# Set the $ARCH variable to the architecture of the CPU - to run on multiple cpu types
# RUN ["export", "ARCH=`dpkg --print-architecture`"]
# Download GH CLI from github
RUN ["curl", "-L", "https://github.com/cli/cli/releases/download/v2.27.0/gh_2.27.0_linux_`dpkg --print-architecture`.deb", "--output", "/tmp/gh.deb"]
# Extract the "gh" command to /usr/bin
# RUN ["dpkg", "-i", "/tmp/gh.deb"]

COPY py-crawler /workspaces/py-crawler/py-crawler
#COPY secrets /py-crawler/secrets

WORKDIR /workspaces/py-crawler

# Check configuration
RUN poetry check

# Install project dependencies
RUN poetry install --no-interaction --no-cache

ENV PLAYBOOKS_DIR="/playbooks"
ENV OUTPUT_DIR="/output"

CMD [ "sh", "/workspaces/py-crawler/fpki-graph-update.sh" ]