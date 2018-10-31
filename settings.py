import os

"""
docker-rpc config file.
"""

MONGODB = {
    'host': os.getenv('MONGODB_PICK_URL', 'mongodb://192.168.1.79/ssrf')
}
