# Local setup

Create a virtual environment, install `backend/requirements.txt`, copy
`backend/.env.example` to `backend/.env`, provide a development secret, and
run migrations with `python manage.py migrate`. Use `DEBUG=True` and local
HTTP cookie settings for development. Never commit `.env`, the SQLite database,
virtual environments, or generated files.
