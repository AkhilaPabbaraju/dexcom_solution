# This is a plan document for Secure Nginx Docker Deployment on GCP
## Prerequisites

- **Docker**: Install Docker
- **GCP**: Create a GCP free trial account
- **Github**: Create a Github account and install Github
- **Trivy/Docker Scout** - Install Trivy & create an accout in Docker scout
- **GCloud** - Install gcloud
- Receive the Dockerfile 

## Tasks
### Task1: Docker Image Preparation

- Create a github repository
- Commit PLAN.md locally
- Build the docker image with the provided Dockerfile

### Task2: 
- Scan the docker image using docker scout and trivy to check any vulnerabilities
- Install Trivy
- Push docker image to docker hub and enable docker scout to check vulnerabilities on UI
- Document the result

### Task 3:
- Categorize the Critical vulnerabilities first to remediate them
- Update the dockerfile with updates in packages
- Verify all the vulnerabilities are fixed by running Trivy & docker scout again

### Task 4:
- Download google cloud libraries
- Create a VPC, subnet, firewall rules and any other resources using python script
- Replace the default service account with scoped service account

### Task 5:
- Enable google artifactory
- Push image to google artifactory
- Deploy the docker container in google cloud compute engine using gcloud
- Verify the nginx webserver deployment using curl command

### Task 6:
- Cleanup all resources created
