#!/bin/sh

#curl -X POST -H "Content-Type: application/json" \
# -d '{"username":    "cs","password": "Cs@1234"}' http://127.0.0.1:8000/login -v

#curl -k http://127.0.0.1:8000/test -v
#curl --http1.1 -X put http://127.0.0.1:8000/test -v
#curl --http1.1 -k http://127.0.0.1:8000/test -v 

printf "\n==> restart_nanomq_service\n"
curl -s http://127.0.0.1:8000/restart_nanomq_service | jq --sort-keys -c

printf "\n==> get_nanomq_status\n"
curl -s http://127.0.0.1:8000/get_nanomq_status | jq --sort-keys -c

# {"code":0,"message":"success","result":{"http_server":{"port":2222},"listeners.ssl":{"port":1111,"verify_peer":true},"log":{"level":"fatal"}}}
printf "\n\n==> get_nanomq_config\n"
curl -s http://127.0.0.1:8000/get_nanomq_config | jq --sort-keys -c

printf "\n\n==> set_nanomq_config\n"
# curl -s http://127.0.0.1:8000/get_nanomq_config | jq --sort-keys -c

# { 
#   "code":0,
#   "message":"success",
#   "result":{
#     "acl_rule":[
#       {"action":"subscribe","id":1,"permit":"allow","topics":["$SYS/#"],"username":"dashboard"},
#       {"id":2,"permit":"allow"},
#     ],
#     "login_auth":[
#       {"id":1,"password":"p1","username":"u1"},
#     ]
#   }
# }
printf "\n\n==> get_mqtt_auth_config\n"
curl -s http://127.0.0.1:8000/get_mqtt_auth_config | jq --sort-keys -c

printf "\n\n==> set_mqtt_auth_config\n"
data="$(curl -s http://127.0.0.1:8000/get_mqtt_auth_config | jq --sort-keys -c)"
curl -s http://127.0.0.1:8000/get_mqtt_auth_config | jq --sort-keys -c
