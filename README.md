# Nginx Access Log Rate Limit Analyser

This script analyses an Nginx access log to determine appropriate rate limit settings based on current traffic patterns. It helps to identify IP addresses with high request rates and suggests rate limit and burst capacity settings to prevent abuse or DoS attacks.

## Requirements

- Python 3.x
- `argparse` module (included in Python standard library)
- `collections` module (included in Python standard library)
- `datetime` module (included in Python standard library)
- `re` module (included in Python standard library)

## Usage

```python3 rate.py /var/log/nginx/access.log```

## Example Output

```
Request rate distribution:
1 requests/second: 2 IPs
2 requests/second: 1 IPs
12 requests/second: 1 IPs

Suggested rate limit settings:
Rate limit: 6 requests/second
Burst capacity: 14 requests
```
