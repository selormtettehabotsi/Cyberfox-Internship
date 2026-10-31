FROM ubuntu:latest
ENV DB_PASSWORD=SuperSecret123
ARG API_KEY=abc123fakekey
ADD https://example.com/app.tar.gz /opt/app.tar.gz
RUN apt-get update && apt-get install -y curl sudo
RUN curl -fsSL https://example.com/install.sh | sh
EXPOSE 22
COPY . /app
CMD ["python3", "/app/main.py"]
