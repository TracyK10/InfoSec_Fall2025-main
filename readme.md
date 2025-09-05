# Information Security Fall 2025 Lab

This guide explains how to set up the Information Security Fall 2025 Lab application locally using Python.  

---

## Prerequisites

- Python 3.10 or higher installed  
- Git (optional, for cloning the repository)  
- Docker (optional, for containerized setup)

# Option I: Local Python Setup

## 1. Create a virtual environment
```bash
python3 -m venv venv
```

## 2. Activate the virtual environment

### Windows (PowerShell):
```powershell
.\venv\Scripts\Activate.ps1 OR ~.\venv\Scripts\Activate.ps1 OR ./venv/bin/activate
```

### Windows (CMD):

```cmd

.\venv\Scripts\activate.bat

```

### Linux / macOS / Git Bash / MSYS:
```bash
source venv/bin/activate
```

## 3. Install required packages
```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

## 4. Run the application
```bash
python app.py
```

### The application will start at:
http://127.0.0.1:5000

---

# Option II: Docker Setup

### On Linux

```shell
docker build -t infosec_lab .
docker run -it -p 5000:5000 \
  -v $(pwd):/app \
  -v $(pwd)/uploads:/app/uploads \
  -v $(pwd)/infosec_lab.db:/app/infosec_lab.db \
  -e FLASK_APP=app.py \
  -e FLASK_ENV=development \
  infosec_lab

```
#### The application will start at:

http://127.0.0.1:5000


### On windows:

```powershell
docker build -t infosec_lab .
docker run -it -p 5000:5000 `
  -v ${PWD}:/app `
  -v ${PWD}/infosec_lab.db:/app/infosec_lab.db `
  -e FLASK_APP=app.py `
  -e FLASK_ENV=development `
  infosec_lab

```
#### The application will start at:

http://127.0.0.1:5000

---

## Features

- Registration with **Name, Andrew ID, and Password**
- Login using **Andrew ID + Password**
- Personalized greeting after login:  
  > Hello {Name}, Welcome to Lab 0 of Information Security course. Enjoy!!!
- Logout returns to the landing page

---

## Database

- SQLite database: `infosec_lab.db`  
- **Schema source of truth:** `schema.sql` (edit here to add tables/columns)  
- Auto-created on first run by executing `schema.sql`  

---

## Folder Structure

```
InfoSec_Fall2025/
│── app.py
│── requirements.txt
│── readme.md
│── schema.sql
│── scripts/
│   └── dump_db.py
    |__ reset_db.py
│── static/
│    └── style.css
│── templates/
│    └── base.html, index.html, login.html, register.html, dashboard.html
└── infosec_lab.db  (auto-created)
```

---

## Script Folder
The project includes a `scripts/` folder with a simple reset utility.  

- Optional reset:
  
```bash
  python scripts/reset_db.py
```
- Optional dump database:

```bash
  python scripts/dump_db.py
```


**Link to download:**

- Python: https://www.python.org/downloads/windows/
- Docker: https://docs.docker.com/get-started/get-docker/
- VScode: https://code.visualstudio.com/download

Note: Youtube Tutorials may help in installation process

- What is Flask? https://flask.palletsprojects.com/en/stable/

