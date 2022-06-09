# Installing Kubelink

## What info you will need

In order to connect your clusters, you should first choose the way of connectivity. The options are:

### connecting the services networks
You can go and simply use kubelink to route all service-networks. This requires to not share IP addresses across these clusters. Each of your service networks requires their own dedicated CIDR. To configure this, you will need the CIDR ranges assigned as your service networks.

### spanning a network of "Network Aliases" or "Business Contexts" 
A unique feature of kubelink is the possibility to add a virtual network range to your mesh which will allow it to communicate with services of other clusters even if these other clusters have overlapping IP space in their service-, pod- or node networks. 

In order to configure this, you will just need to define where the virtual ranges shall live and create the respective kubelinks

## Getting started

### generating configuration files

- move into the folder ./magic
- fill out the values.yaml according to your cluster needs (service networks, etc.)
- execute `./gen.sh`
- You will find the configuration files in the folder ./magic/gen/kubelink{#}
- There will be a folder for each cluster as you defined in the values.yaml
- additionally, you should add the yaml files from ./examples:
	- `52-policy.yaml`
	- `10-crds.yaml`


apply these to your cluster to enable dns communication and adding the required CRDs for Kubelink. The CRDs should be added by the kubelink binary, but if required you can do this manually via the 10-crds.yaml file


### Applying the configuration

- create a dedicated namespace for kubelink e.g. `kubectl create ns kubelink`
- apply the files from the ./magic/gen/kubelink{#} files
- apply the files from ./examples if necessary

Next double-check, that everything is running:
`kubectl -n kubelink get pod`
- There should be one pod per node called kubelink-router-xxxx
- There should be one pod for the kubelink-broker
- There should be two pods for the kubelink-dns
- All of the pods should be in running state

`kubectl -n kubelink get svc`
- There should be a Type Loadbalancer service for UDP port 8777 pointing to the kubelink-broker

`kubectl -n kubelink get kubelink`
This should show all of the configured kubelinks. Ensure that they have the state "up" everywhere.

### Further Debugging

You can login to the broker pod and check the status of wireguard tunnels:
`kubectl -n kubelink exec -ti kubelink-broker-xxxx -- /bin/bash`



