FROM python:3.11-alpine

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1


COPY ./requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY . /server
WORKDIR /server

ENV PYTHONPATH=/server

# Use uvicorn CLI directly
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]