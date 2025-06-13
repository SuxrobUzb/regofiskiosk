# Используем официальный минимальный образ Python
FROM python:3.11-slim

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Копируем файл зависимостей
COPY requirements.txt .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем всё приложение в контейнер
COPY . .

# Создаём папку для QR-кодов (если её нет)
RUN mkdir -p qrcodes

# Открываем порт для Flask/SocketIO
EXPOSE 5000

# Устанавливаем переменные окружения для Flask
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000
# FLASK_EXTERNAL_URL можно установить через docker-compose или вручную при запуске

# Запускаем приложение через Gunicorn с поддержкой WebSocket (gevent)
CMD ["gunicorn", "--worker-class", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker", "-w", "1", "-b", "0.0.0.0:5000", "app:app"]