# RDX Works Application Builder

Setting up a build environment for the Radix Ledger App is quite painful process and the setup works only for 
Linux and only on x86 hardware. To overcome these limitations, developer can use a Docker image with pre-configured
development environment setup. 

This directory contains Docker configuration file and necessary files to build an image with build environment inside.
Once image is built, it can be used to build Radix Ledger App binaries.

### Application Builder Image Build
In order to build the image, it is enough to issue following command in the directory where `Dockerfile` resides:
Build image:
```sh
docker build -t app-radix-builder:latest .

```
In some cases command may require `sudo` to obtain necessary privileges.

### Using Application Builder Image
Go to project directory and execute following command:
(just like image building, this command may require use of `sudo` to obtain necessary privileges)

```sh
docker run --rm -ti -v "$(realpath .):/app" app-radix-builder:latest
```
The command above opens a shell with project directory linked to `/app` directory inside image. 
This enables convenient building of the binaries and transparent sharing of the files between project directory on the host
machine and `/app` directory inside the image.
