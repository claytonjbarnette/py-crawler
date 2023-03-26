FROM python:3.11-slim
RUN ["apt", "-y", "update"]
RUN ["apt", "-y", "install", "openjdk-17-jre-headless"]
COPY cert-report /cert-report
RUN pip install -r /cert-report/requirements.txt
WORKDIR /cert-report
ENTRYPOINT [ "python", "-m", "certreport", "/certs" ]