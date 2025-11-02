FROM python:3.9-slim
WORKDIR /app
RUN pip install flask
COPY vulnerable_app.py .
CMD ["python", "vulnerable_app.py"]
