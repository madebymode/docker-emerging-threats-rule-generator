FROM alpine:3.23

RUN apk add --no-cache logrotate

COPY logrotate.conf /etc/logrotate.d/nginx-blocklist
COPY rotate        /etc/periodic/daily/nginx-blocklist-rotate
RUN chmod +x /etc/periodic/daily/nginx-blocklist-rotate

# Run busybox crond in the foreground as PID 1.
# -d 8 = log level (notice); crond executes /etc/periodic/daily/* once per day.
CMD ["crond", "-f", "-d", "8"]
