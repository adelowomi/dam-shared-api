# Switch to Debian-based Node image
# Use the Debian-based Node image
FROM node:20-buster-slim

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app
RUN apt-get update && apt-get install -y bash


EXPOSE 80
EXPOSE 443

COPY ./startup.relational.dev.sh /opt/startup.relational.dev.sh
RUN chmod +x /opt/startup.relational.dev.sh


COPY tsconfig.build.json ./
COPY tsconfig.json ./
COPY package.json ./
COPY package-lock.json ./
COPY .env ./
RUN npm install
ADD ./src ./src
# ADD ./db ./db

RUN npm run build

# CMD [ "node", "dist/src/main.js" ]

# # Install bash and other dependencies
# RUN apt-get update && apt-get install -y bash
# RUN npm i -g @nestjs/cli typescript ts-node

# COPY package*.json /tmp/app/
# RUN cd /tmp/app && npm install

# COPY . /usr/src/app
# RUN cp -a /tmp/app/node_modules /usr/src/app
# COPY ./wait-for-it.sh /opt/wait-for-it.sh
# RUN chmod +x /opt/wait-for-it.sh
# COPY ./startup.relational.dev.sh /opt/startup.relational.dev.sh
# RUN chmod +x /opt/startup.relational.dev.sh
# RUN sed -i 's/\r//g' /opt/wait-for-it.sh
# RUN sed -i 's/\r//g' /opt/startup.relational.dev.sh

# WORKDIR /usr/src/app
# RUN if [ ! -f .env ]; then cp env-example-relational .env; fi
# RUN npm run build

CMD ["/opt/startup.relational.dev.sh"]
