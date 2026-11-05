FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY backend/requirements.lock.txt /app/backend/requirements.lock.txt
RUN pip install --no-cache-dir -r backend/requirements.lock.txt
COPY backend /app/backend
COPY alembic.ini /app/alembic.ini
RUN useradd --uid 10001 --create-home phishscope && mkdir /app/data && chown phishscope:phishscope /app/data
USER phishscope
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
