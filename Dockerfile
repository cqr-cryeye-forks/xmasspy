FROM python:3.9-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt

COPY . .
RUN chmod +x xmasspy_modified.py
RUN chmod +x xmasspy.py
ENTRYPOINT ["python3", "xmasspy_modified.py"]
CMD ["--verbose"]