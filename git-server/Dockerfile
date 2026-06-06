FROM alpine:3.22.4

# install packages
RUN apk add git openssh-server

# set up ssh
EXPOSE 22
RUN ssh-keygen -A

# really make sure only ssh key authentication is enabled
RUN echo "PubKeyAuthentication yes" >> /etc/ssh/sshd_config
RUN echo "PasswordAuthentication no" >> /etc/ssh/sshd_config

# create git user wish correct ssh keys
RUN adduser -Dh /home/git git
RUN passwd -u git
COPY ./authorized_keys /home/git/.ssh/authorized_keys
RUN chown -R git:git /home/git
RUN chmod 700 /home/git/.ssh
RUN chmod 600 /home/git/.ssh/authorized_keys

ENTRYPOINT /usr/sbin/sshd -D
