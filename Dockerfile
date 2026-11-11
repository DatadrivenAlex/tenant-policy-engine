FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY policy_engine ./policy_engine
RUN pip install --no-cache-dir . && useradd --create-home app
USER app
EXPOSE 8000
CMD ["uvicorn", "policy_engine.api:app", "--host", "0.0.0.0", "--port", "8000"]
