# msegroups-login-service

#Sample flask application for login & logout flow
To run:
1. run pip install -r requirements.txt
2. python3 app/app.py

It is however recommended to use it together with pepm_compose

Environment variables should not be committed into source files, will provide if requested

Routes:

/login: logs redirects to cognito for login, and redirects to /postlogin when done. See /app/config.py for env variables required

/profile: returns the user email from the jwt cookie