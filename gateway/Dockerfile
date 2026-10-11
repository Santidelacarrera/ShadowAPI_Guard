# build context: repository root (shares control-plane/app/pii.py)
FROM python:3.12-slim
WORKDIR /srv
COPY gateway/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY gateway/*.py ./
COPY control-plane/app/pii.py ./pii.py
RUN useradd -r -u 10001 app
USER app
EXPOSE 9000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9000"]
