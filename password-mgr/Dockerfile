FROM python:3.15.0b2-trixie

ENV DB_PATH=database.sqlite
EXPOSE 8080

# install packages
RUN pip install --root-user-action=ignore -U pip fastapi uvicorn

# create non-admin user
RUN useradd -p user user
RUN passwd -u user

# copy python files
COPY src /home/user/app
RUN chown -R user:user /home/user

USER user

# using exec to forward events to python
ENTRYPOINT cd /home/user/app; exec python -m uvicorn main:app --host 0.0.0.0 --port 8080
