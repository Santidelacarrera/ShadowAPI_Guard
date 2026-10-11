FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml ./
COPY src src
RUN pip install --no-cache-dir . && useradd -r -u 10001 guard
USER guard
EXPOSE 8080
CMD ["python", "-m", "edge_gateway"]
