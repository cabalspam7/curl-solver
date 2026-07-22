FROM python:3.13-slim-trixie

# Install Chromium + deps for nodriver fallback
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium chromium-driver \
    fonts-liberation libnss3 libxss1 libasound2t64 \
    libatk-bridge2.0-0 libgtk-3-0 libgbm1 \
    libx11-xcb1 xdg-utils wget xvfb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

ENV PORT=8080
ENV CHROME_PATH=/usr/bin/chromium
EXPOSE 8080

CMD ["sh", "-c", "python app.py"]
