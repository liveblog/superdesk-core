rest: gunicorn -c gunicorn_config.py wsgi
wamp: python3 -u ws.py
work: celery -A worker worker
beat: celery -A worker beat --pid=
