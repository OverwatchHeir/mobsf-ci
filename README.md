
# Mobile Security Framework CI

We expect our mobile app to be secure and that is keeping it secure even when the code change. This is why we need to integrate the security testing activities in a CI.

Therefore we will use an open-source security tool focused on static analysis security testing called [Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF). As well, a Python script that interacts with the Mobile Security Framework REST API will be used to upload an app, initiate a scan and obtain a report.

## Docker App

Running this repository in the CI, would allow you to find security issues earlier, and fix them before a release. Here's how it works:

**Architecture**
1. Docker container running the Mobile Security Framework
2. Docker container running our scan Python script 

## Requirements

In order to use this repository, the following requirements must be fullfiled:

- Install [Docker](https://docs.docker.com/engine/install/)
- Install [Docker-Compose](https://docs.docker.com/compose/install/)
- Enable Docker [experimental features](https://docs.docker.com/app/working-with-app/)
    
## Usage

Get the Docker App image from Docker Hub:
```
docker pull overwatchheir/mobsf-ci.dockerapp:latest-invoc
```

The easiest way to use this repository is by using [docker app](https://docs.docker.com/app/working-with-app/). Simply run:
```
docker app render overwatchheir/mobsf-ci.dockerapp:latest --set target_folder=<path to the folder that contains the APK> --set target_apk=<apk name> --set output_folder=<path to folder where the report will be written> | docker-compose -f - up --exit-code-from scan
```

## CI Integration 

To integrate this repository into your CI and perform automated security tests you have to add the Docker App image to the YAML file 
and run it as mentioned above.