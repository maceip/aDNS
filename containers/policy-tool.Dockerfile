FROM --platform=linux/amd64 mcr.microsoft.com/azure-cli:2.85.0@sha256:7f9ca8e6bf1c72e5fafefb6925546272776d635fb428538455c5c79bb77e2aa7
RUN az extension add --name confcom --version 2.1.0 --yes
WORKDIR /work
ENTRYPOINT ["az", "confcom", "acipolicygen"]
