FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ /app/src
COPY config/ /app/config

CMD ["python", "src/main.py"]