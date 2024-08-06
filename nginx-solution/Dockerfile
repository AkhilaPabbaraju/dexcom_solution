FROM nginx:1.27-alpine
RUN apk update 
RUN apk upgrade
RUN apk add curl libcurl
EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
