FROM caddy:2.7-alpine

# Copy the JSON config
COPY caddy.json /etc/caddy/config.json

# Copy the website files
COPY index.html /app/mount/website/

# Expose the default HTTP and HTTPS ports
EXPOSE 80 443

# Override the default command to use JSON config
CMD ["caddy", "run", "--config", "/etc/caddy/config.json"] 