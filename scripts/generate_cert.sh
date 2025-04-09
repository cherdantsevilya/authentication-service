#!/bin/bash

# Создаем директорию для сертификатов
mkdir -p config

# Генерируем приватный ключ
openssl genrsa -out config/key.pem 2048

# Генерируем CSR (Certificate Signing Request)
openssl req -new -key config/key.pem -out config/csr.pem -subj "/CN=localhost/O=Auth Service/C=RU"

# Генерируем self-signed сертификат
openssl x509 -req -days 365 -in config/csr.pem -signkey config/key.pem -out config/cert.pem

# Удаляем временный CSR файл
rm config/csr.pem

echo "Self-signed certificates generated successfully!"
echo "Location: config/cert.pem and config/key.pem" 