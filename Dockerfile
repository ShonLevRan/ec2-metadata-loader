# Dockerfile

FROM python:3.9-slim

WORKDIR /app

RUN apt update
RUN apt install tshark -y

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY register_node.py .

ENTRYPOINT ["python", "register_node.py"]

