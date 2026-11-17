# syntax=docker/dockerfile:1
ARG PY=3.12
FROM python:${PY} AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential
COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

FROM python:${PY}-slim
COPY --from=build /install /usr/local
COPY . /app
CMD ["python", "/app/main.py"]
