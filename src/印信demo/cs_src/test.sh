#!/bin/sh

#curl -X POST -H "Content-Type: application/json" \
# -d '{"username":    "cs","password": "Cs@1234"}' http://127.0.0.1:8000/login -v

curl -k http://127.0.0.1:8000/test -v
#curl --http1.1 -X put http://127.0.0.1:8000/test -v
#curl --http1.1 -k http://127.0.0.1:8000/test -v 
