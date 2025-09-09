# Starten mit einem schlanken Python-Basisimage
FROM python:3.12-slim

# Setzen des Arbeitsverzeichnisses im Container
WORKDIR /app

# Kopieren der Anforderungsdatei
COPY requirements.txt .

# Installieren der Python-Abhängigkeiten
# --no-cache-dir reduziert die Image-Größe
RUN pip install --no-cache-dir -r requirements.txt

# Kopieren des restlichen Quellcodes in den Container
COPY . .

# Der Befehl, der beim Starten des Containers ausgeführt wird
CMD ["python", "collector.py"]
