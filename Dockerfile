FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY isis_lsdb_parser.py .
ENTRYPOINT ["python", "isis_lsdb_parser.py"]
