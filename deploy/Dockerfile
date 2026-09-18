FROM python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY contract ./contract
RUN pip install --no-cache-dir .
USER 65532:65532
EXPOSE 8080
CMD ["python", "-m", "attendance_backend.runtime_server"]
