"""Least-privilege configuration view with a server change timestamp."""
from datetime import datetime, timezone

FIELDS = ('id', 'name', 'target', 'source_type', 'source', 'enforcement',
          'conditions', 'rules', 'updated_at')


def visible(item):
    result = {key: item[key] for key in FIELDS}
    result['updated_at'] = datetime.fromisoformat(result['updated_at'].replace('Z', '+00:00')).astimezone(
        timezone.utc).isoformat(timespec='milliseconds')
    return result
