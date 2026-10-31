# Week 3 evaluation

Real-world test set: 28 files (15 Dockerfiles, 13 compose files) sampled from four public
open-source repositories on 31 October 2026. Sampling is reproducible: all Dockerfiles and compose
files in the repositories were pooled, shuffled with Python random seed 42, and drawn with a cap
per repository (Dockerfiles: 15 total, 6 per repo; compose: 15 total, 10 per repo).
Only 13 compose files were available under the cap.

Files are copied unmodified into testset/ with the original licences in licenses/ (CC0-1.0, MIT, Apache-2.0).
manifest.json records the source repository, commit, licence and original path of every file.

## Reproduce

    python -m dockerscan evaluation/testset --format json --fail-on never
    trivy config --skip-check-update --format json evaluation/testset
    checkov -d evaluation/testset --quiet -o json
    for f in evaluation/testset/dockerfile/*/*; do hadolint --format json "$f"; done

Tool versions used: Trivy 0.76.1, Checkov 3.4.0, Hadolint 2.15.1, dockerscan 0.2.0.
raw_outputs/ holds the saved results (dockerscan before and after tuning).

## Source commits

- github.com/GoogleCloudPlatform/microservices-demo at c7cb6d5bfd6e (Apache-2.0)
- github.com/docker/awesome-compose at 30f4b7f6a6c3 (CC0-1.0)
- github.com/fastapi/full-stack-fastapi-template at f4bcfaba7c85 (MIT)
- github.com/nodejs/docker-node at 14b1d124e21d (MIT)

## Files

| # | Type | Source repo | Licence | Path in repo |
|---|------|-------------|---------|--------------|
| 1 | dockerfile | github.com/GoogleCloudPlatform/microservices-demo | Apache-2.0 | src/loadgenerator/Dockerfile |
| 2 | dockerfile | github.com/GoogleCloudPlatform/microservices-demo | Apache-2.0 | src/productcatalogservice/Dockerfile |
| 3 | dockerfile | github.com/GoogleCloudPlatform/microservices-demo | Apache-2.0 | src/shippingservice/Dockerfile |
| 4 | dockerfile | github.com/docker/awesome-compose | CC0-1.0 | aspnet-mssql/app/aspnetapp/Dockerfile |
| 5 | dockerfile | github.com/docker/awesome-compose | CC0-1.0 | django/app/Dockerfile |
| 6 | dockerfile | github.com/docker/awesome-compose | CC0-1.0 | nginx-golang-mysql/backend/Dockerfile |
| 7 | dockerfile | github.com/docker/awesome-compose | CC0-1.0 | nginx-nodejs-redis/web/Dockerfile |
| 8 | dockerfile | github.com/docker/awesome-compose | CC0-1.0 | react-express-mongodb/frontend/Dockerfile |
| 9 | dockerfile | github.com/docker/awesome-compose | CC0-1.0 | traefik-golang/backend/Dockerfile |
| 10 | dockerfile | github.com/fastapi/full-stack-fastapi-template | MIT | frontend/Dockerfile.playwright |
| 11 | dockerfile | github.com/nodejs/docker-node | MIT | 22/alpine3.23/Dockerfile |
| 12 | dockerfile | github.com/nodejs/docker-node | MIT | 24/bookworm-slim/Dockerfile |
| 13 | dockerfile | github.com/nodejs/docker-node | MIT | 24/bookworm/Dockerfile |
| 14 | dockerfile | github.com/nodejs/docker-node | MIT | 26/alpine3.23/Dockerfile |
| 15 | dockerfile | github.com/nodejs/docker-node | MIT | 26/bookworm-slim/Dockerfile |
| 16 | compose | github.com/docker/awesome-compose | CC0-1.0 | aspnet-mssql/compose.yaml |
| 17 | compose | github.com/docker/awesome-compose | CC0-1.0 | django/compose.yaml |
| 18 | compose | github.com/docker/awesome-compose | CC0-1.0 | minecraft/compose.yaml |
| 19 | compose | github.com/docker/awesome-compose | CC0-1.0 | nextcloud-redis-mariadb/compose.yaml |
| 20 | compose | github.com/docker/awesome-compose | CC0-1.0 | nginx-golang-mysql/compose.yaml |
| 21 | compose | github.com/docker/awesome-compose | CC0-1.0 | nginx-golang-postgres/compose.yaml |
| 22 | compose | github.com/docker/awesome-compose | CC0-1.0 | plex/compose.yaml |
| 23 | compose | github.com/docker/awesome-compose | CC0-1.0 | react-express-mysql/compose.yaml |
| 24 | compose | github.com/docker/awesome-compose | CC0-1.0 | sparkjava-mysql/compose.yaml |
| 25 | compose | github.com/docker/awesome-compose | CC0-1.0 | sparkjava/compose.yaml |
| 26 | compose | github.com/fastapi/full-stack-fastapi-template | MIT | compose.deploy.yml |
| 27 | compose | github.com/fastapi/full-stack-fastapi-template | MIT | compose.override.yml |
| 28 | compose | github.com/fastapi/full-stack-fastapi-template | MIT | compose.yml |
