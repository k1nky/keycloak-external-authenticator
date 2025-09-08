FROM python:3.11

WORKDIR /app
COPY requirements.txt ./

RUN pip install -r requirements.txt

CMD ["uvicorn", "--host", "0.0.0.0", "main:app", "--port", "8000"]


