FROM python:3.14-alpine

WORKDIR /app
COPY api/ .

RUN pip install --no-cache-dir flask bcrypt

EXPOSE 5000
CMD ["python", "app.py"]