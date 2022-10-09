FROM nginx

# Remove the default Nginx configuration file
RUN rm /etc/nginx/conf.d/default.conf

# Copy the nginx.conf file to the /etc/nginx directory
COPY nginx.conf /etc/nginx/conf.d/