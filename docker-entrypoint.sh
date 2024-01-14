#!/bin/sh
# Adjust permissions of /app/nginx/conf/
chown -R anubis:rites /app/nginx/conf/

# Execute the main container command as a specific user
exec su-exec anubis:rites "$@"
