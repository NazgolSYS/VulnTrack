# VulnTrack

**VulnTrack** is a cybersecurity vulnerability management and risk tracking platform built with Python, FastAPI, and PostgreSQL. It provides a centralized way to manage assets, track vulnerabilities, assess security risks, prioritize remediation, and monitor vulnerability management activities.

## Key Features

- **Asset Management:** Register and manage assets within the environment.
- **Software Management:** Maintain software records and associate software with assets.
- **Vulnerability Management:** Track vulnerabilities, their severity, status, and associated assets.
- **Security Findings:** Integrate scan findings with vulnerability records, including CVE identification.
- **Scan Management:** Manage scan records and their lifecycle.
- **Vulnerability Status Workflow:** Track vulnerability status transitions and maintain vulnerability history.
- **Risk Assessment:** Calculate risk scores based on likelihood and impact.
- **Risk-Based Prioritization:** Prioritize vulnerabilities using risk assessments and severity.
- **Remediation Management:** Create and manage remediation tasks.
- **Dashboard:** Provide an overview of vulnerability management information.
- **Audit Logging:** Record relevant system activities.
- **Comments:** Support comments associated with managed records.
- **Authentication and Role-Based Access Control (RBAC):** Secure API endpoints using JWT authentication and role-based permissions.

## Technology Stack

| Component | Technology |
|---|---|
| Backend Framework | FastAPI |
| Programming Language | Python |
| Database | PostgreSQL 17 |
| ORM | SQLAlchemy |
| Database Migrations | Alembic |
| Authentication | JWT (PyJWT) |
| Password Hashing | Argon2 (pwdlib) |
| Configuration | Pydantic Settings |
| API Server | Uvicorn |
| Containerization | Docker |
| Container Orchestration | Docker Compose |
| Testing | Pytest and HTTPX |

## Architecture

VulnTrack follows a layered application architecture:

- **Routers:** Define API endpoints and handle incoming HTTP requests.
- **Schemas:** Define request validation and response structures using Pydantic.
- **Services:** Contain application logic and database operations.
- **Models:** Define database entities using SQLAlchemy.
- **Core:** Contains application configuration, authentication dependencies, and role definitions.
- **Database:** Manages database connectivity and SQLAlchemy sessions.

PostgreSQL stores application data, while Alembic manages database schema migrations.

## Project Structure

```text
VulnTrack/
│
├── alembic/
│   └── versions/
│
├── app/
│   ├── core/
│   ├── routers/
│   ├── schemas/
│   ├── services/
│   ├── database.py
│   ├── main.py
│   └── models.py
│
├── tests/
│
├── .dockerignore
├── .gitignore
├── alembic.ini
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## Installation and Setup

### Prerequisites

- Python 3.14 or compatible version
- PostgreSQL
- Git

### 1. Clone the repository

```bash
git clone https://github.com/Nazgol-sys/VulnTrack.git
cd VulnTrack
```

### 2. Create and activate a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements-dev.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root.

Configure the following variables:

```env
DATABASE_URL=postgresql://<username>:<password>@localhost:5432/<database_name>
JWT_SECRET_KEY=<your-secret-key>
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

Replace the database placeholders with your PostgreSQL credentials and database name. Use a strong, randomly generated JWT secret.

Do not commit `.env` or other files containing credentials or secrets.

### 5. Apply database migrations

Make sure PostgreSQL is running and the configured database exists.

Run:

```powershell
alembic upgrade head
```

### 6. Start the application

```powershell
uvicorn app.main:app --reload
```

The API will be available at:

```text
http://127.0.0.1:8000
```

## Docker Deployment

VulnTrack includes a Dockerfile and Docker Compose configuration for running the API and PostgreSQL in separate containers.

### 1. Configure Docker environment variables

Create a `.env.docker` file in the project root with the following variables:

```env
POSTGRES_DB=<database_name>
POSTGRES_USER=<database_user>
POSTGRES_PASSWORD=<database_password>

DATABASE_URL=postgresql://<database_user>:<database_password>@db:5432/<database_name>

JWT_SECRET_KEY=<your-secret-key>
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

Use matching PostgreSQL credentials in `POSTGRES_USER`, `POSTGRES_PASSWORD`, and `DATABASE_URL`.

### 2. Build and start the containers

```powershell
docker compose --env-file .env.docker up --build -d
```

### 3. Check container status

```powershell
docker compose --env-file .env.docker ps
```

The API and database containers include health checks. The API container waits for PostgreSQL to become healthy before starting.

### 4. Apply database migrations

```powershell
docker compose --env-file .env.docker exec api alembic upgrade head
```

### 5. Stop the containers

```powershell
docker compose --env-file .env.docker down
```

The PostgreSQL data is stored in a named Docker volume (`vulntrack_postgres_data`) and is retained when containers are stopped or removed.

**Note:** Avoid using `docker compose down -v` unless you intentionally want to delete the persistent database volume and its data.

## Database Migrations

Alembic is used to manage database schema changes.

Apply all pending migrations:

```powershell
alembic upgrade head
```

Check the current migration revision:

```powershell
alembic current
```

View migration history:

```powershell
alembic history
```

The project currently includes an initial database migration and a subsequent migration for risk assessments and additional tables.

## API Documentation

VulnTrack uses FastAPI to provide interactive API documentation.

After starting the application, access:

| Resource | URL |
|---|---|
| Swagger UI | http://127.0.0.1:8000/docs |
| ReDoc | http://127.0.0.1:8000/redoc |
| OpenAPI Schema | http://127.0.0.1:8000/openapi.json |
| Health Check | http://127.0.0.1:8000/health |

The health endpoint reports the application status and database connectivity status. A successful response returns "status": "ok" and "database": "connected".

## Authentication and Authorization

VulnTrack uses JWT bearer-token authentication.

### Login

Authenticate through:

```http
POST /auth/login
```

Example request:

```json
{
  "username": "your_username",
  "password": "your_password"
}
```

A successful login returns an access token.

For protected endpoints, include the token in the HTTP authorization header:

```http
Authorization: Bearer <access_token>
```

The default access-token expiration is 30 minutes and is configurable through environment variables.

### Role-Based Access Control

The application defines three roles:

| Role | Permissions |
|---|---|
| Administrator | Administrative access and permitted security management operations |
| Security Analyst | Security management and analysis operations |
| Viewer | Read access to permitted resources |

Access to protected endpoints is controlled through role-based authorization dependencies.

## Risk Assessment and Prioritization

VulnTrack calculates risk scores using likelihood and impact values, each ranging from 1 to 5.

**Risk Score = Likelihood × Impact**

| Risk Score | Risk Level |
|---|---|
| 1–4 | Low |
| 5–9 | Medium |
| 10–15 | High |
| 16–25 | Critical |

Vulnerability prioritization considers risk assessment levels and scores, with vulnerability severity used as an additional prioritization factor.

## Testing

The project uses Pytest and HTTPX for automated testing.

Install development dependencies:

```powershell
python -m pip install -r requirements-dev.txt
```

Run the complete test suite:

```powershell
python -m pytest -q
```

Run a specific test file:

```powershell
python -m pytest tests/test_rbac.py -v
```

The test suite covers authentication, authorization, vulnerability workflows, scan lifecycle, risk assessment, prioritization, remediation, dashboard functionality, and audit logging.

## Future Improvements

Potential future enhancements include:

- Integration with external vulnerability scanning tools.
- Advanced vulnerability analytics and reporting.
- Additional security monitoring and notification capabilities.
- Expanded automated integration and deployment testing.


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
