# Uncle Roger's Wok Way (URWW) MVP

A MVP has been developed to give Uncle Roger an idea on how an online store might look like. A demo is available [here](https://daremvp.southeastasia.cloudapp.azure.com:8443/).

## Site Infrastructure
The following image summarises the overall infrastructure of the web application.
![Site Infrastructure](https://github.com/ZhiYuanWPF/URWW-MVP/blob/main/Site%20Infra.png)

## Setting up for Local Run

Even though the MVP has been deployed on Azure, a local version can be setup as well. The connection string to Mongo Atlas is not provided because local connections to it is slow and results in poor performance of the MVP. Therefore, MongoDB is required to be set up locally for the local run.

Pre-requisites:
- Python (Preferably at least version 3.8)
- MongoDB (Preferably at least version 4.4.1)

### Steps for set up
Obtain project files from GitHub:


```bash
git clone https://github.com/ZhiYuanWPF/URWW-MVP.git
```
With a Python interpreter (local or virtual environment), install the required Python packages using Pip:
```bash
pip install -r requirements.txt
```
The python environment has been set up. The MongoDB server should be running before the Python script is executed to spawn the web server. To run the script, please provide the MongoDB connection string as a parameter. The  script will create the necessary database and collections on the fly during execution.
```bash
python3 main.py {MONGODB_CONNECTION_STRING}
```

## MVP Functionalities
- All required CRUD operations
- Items are designed with the required attributes
- JSON responses are returned from backend API server
- Frontend website to interact with backend API server to perform CRUD with required pages and forms
- Basic user authentication
- Users can proceed to enroll themselves and login to access the management page

## Completed Objectives
- Input validation is done using regex for all user input, done on the backend API server, as well as on the frontend to reduce backend server load
- Logging is enabled, log format is designed to follow the generic Microsoft W3C Extended format for easy ingestion / integration with modern Syslog servers / SIEM / SOAR solutions like Splunk (can be shown in demo, sample provided [here](https://github.com/ZhiYuanWPF/URWW-MVP/tree/main/logs)).
- Authentication checks have been implemented on API endpoints with privileged access
- Ubuntu native iptables and Azure Network ACL configured
- Bcrypt used to salt and hash password at rest
- Password complexity is configured for all users during user enrollment
- 2FA authentication is integrated as part of user enrollment and login process using TOTP ([RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238))
- Rate limiting enabled at web server level to prevent brute force attacks
- Error Handling: HTTP 404 errors
- HTTPS configurations enforced with strong cipher suites (just require an issued certificate from CA to replace self-signed certificate if this goes live)

## Additional Features
- Mongo Atlas Database-as-a-service deployed
- Web server publicly available on Azure VM
- Responsive website design to cater for both mobile and desktop based clients

## Thank you!
Please feel free me contact me at zhiyuancode@gmail.com if required.