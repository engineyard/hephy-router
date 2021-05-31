# EYK Router v2

### Description

The Router is the main entry point for external incoming traffic on an EYK cluster.  In handles routing HTTP traffic based on domain it's targeted to, effectively routing it to the apps running on different namespaces.

Although renamed, this is a clone of the Hephy/Deis Router, with extensions and some rebranding done by Engine Yard.
Note: work from Engine Yard is versioned on the 'ey-master' branch.

### Development

## Prerequisites

### Docker

Unit tests and code linters for controller run in a Docker container with your local code directory
mounted in. You need [Docker][] to run `make test`.

### EYK Installation

You'll want to test your code changes interactively in a working EYK cluster. Use the [EYK UI](https://eyk.ey.io) to create a testing cluster on a staging account of your choice (recommended to use 'ky-dredd').

### Testing Your Code

When you've built your new feature or fixed a bug, make sure you've added appropriate unit tests and run `make test` to ensure your code works properly.

Also, since this component is central to the platform, it's recommended that you manually test and verify that your feature or fix works as expected. To do so, ensure the following environment variables are set:

* `DEIS_REGISTRY` - A Docker registry that you have push access to and your Kubernetes cluster can pull from
  * If this is [Docker Hub](https://hub.docker.com/), leave this variable empty
  * Otherwise, ensure it has a trailing `/`. For example, if you're using [Quay.io](https://quay.io), use `quay.io/`
* `IMAGE_PREFIX` - The organization in the Docker repository. This defaults to `deis`, but if you don't have access to that organization, set this to one you have push access to.
* `SHORT_NAME` (optional) - The name of the image. This defaults to `controller`
* `VERSION` (optional) - The tag of the Docker image. This defaults to the current Git SHA (the output of `git rev-parse --short HEAD`)

Then, run `make deploy` to build and push a new Docker image with your changes and replace the existing one with your new one in the Kubernetes cluster. See below for an example with appropriate environment variables.

```console
export DEIS_REGISTRY=quay.io/
export IMAGE_PREFIX=arschles
make deploy
```

After the `make deploy` finishes, a new pod will be launched but may not be running. You'll need to wait until the pod is listed as `Running` and the value in its `Ready` column is `1/1`. Use the following command watch the pod's status:

```console
kubectl get pod --namespace=deis -w | grep deis-router
```

### Distributing
EYK router is integrated into ky-infrastructure, and thus distributed through new releases of ky-infrastructure.  The later references which version of controller is included on each release.  As such, having the images properly tagged and uploaded to DockerHub should be enough to accomplish this.