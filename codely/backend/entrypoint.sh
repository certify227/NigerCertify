#!/bin/bash
set -e

echo "⏳ Attente de PostgreSQL..."
while ! python -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('${POSTGRES_HOST:-db}', ${POSTGRES_PORT:-5432}))" 2>/dev/null; do
  sleep 1
done
echo "✅ PostgreSQL prêt"

python manage.py migrate --noinput
python manage.py seed_demo_data
python manage.py seed_code_exercises

if [ "${DJANGO_SUPERUSER_USERNAME}" ]; then
  python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='${DJANGO_SUPERUSER_USERNAME}').exists():
    User.objects.create_superuser('${DJANGO_SUPERUSER_USERNAME}', '${DJANGO_SUPERUSER_EMAIL:-admin@codequest.app}', '${DJANGO_SUPERUSER_PASSWORD:-admin}')
"
fi

exec gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3
