FROM python:3.15.0b2-trixie

EXPOSE 80

# install packages
RUN pip install --root-user-action=ignore -U pip fastapi pynacl cryptography uvicorn
RUN apt-get update && apt-get install -y nginx

# create non-admin user
RUN useradd -p user user
RUN passwd -u user

# copy backend files
COPY backend /home/user/app
RUN chown -R user:user /home/user

# copy frontend files
COPY nginx.conf /etc/nginx/nginx.conf
COPY frontend /usr/share/nginx/html
# allow nginx to run fully on a non-root user
RUN chown -R user:user /etc/nginx/nginx.conf /usr/share/nginx /var/log/nginx /var/lib/nginx /run

USER user
WORKDIR /home/user/app

CMD nginx && uvicorn main:app --host 0.0.0.0 --port 8000
