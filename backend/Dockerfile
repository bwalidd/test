# backend/Dockerfile

FROM python:3.9

WORKDIR /app

COPY . /app/

RUN pip install -r requirements.txt
RUN pip install -U channels[daphne]
RUN pip install channels-redis
RUN pip install requests

EXPOSE 8001

ENV PYTHONUNBUFFERED=1

CMD ["sh", "-c", "python manage.py migrate && python manage.py createadmin && python manage.py runserver 0.0.0.0:8001"]
