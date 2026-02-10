# SIEM Project (Django + Elasticsearch + Kibana)

A simple SIEM (Security Information and Event Management) system that logs user authentication events from Django to Elasticsearch and visualizes them in Kibana.

## 🏗 Architecture
- **Django**: Web application & authentication provider.
- **Elasticsearch**: Aggregates logs.
- **Kibana**: Dashboard for log analysis.

## 🚀 Quick Start (Fresh Laptop)

### Prerequisites
1.  **Docker & Docker Compose** installed.
2.  **Python 3.10+** installed.
3.  **Git** installed.

### 1. Backend Infrastructure (Docker)
Start the database and dashboard first.
```bash
# From the project root (where docker-compose.yml is)
docker compose up -d
```
*Wait ~30 seconds for Elasticsearch and Kibana to initialize.*

### 2. Start Django App
Open a terminal in `siem_project/` and run:
```bash
source venv/bin/activate  # Activate the existing virtual environment
python manage.py runserver
```

## 🔄 Restarting After Reboot

If you restart your computer, follow these steps to get everything running again:

### 1. Start Infrastructure (Docker)
Open a terminal in the project folder and run:
```bash
docker compose up -d
```
*Wait ~30 seconds for Elasticsearch and Kibana to initialize.*

### 2. Start Django App
Open a terminal in `siem_project/` and run:
```bash
source venv/bin/activate  # Activate the existing virtual environment
python manage.py runserver
```

