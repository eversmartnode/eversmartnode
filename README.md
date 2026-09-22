This works on evrPanel nodes, it has a frontend on gptcp1.

Docker: eversmartnode/eversmartnode:latest
Github: ghcr.io/eversmartnode/eversmartnode:latest

How it works:

You deploy it to an evrPanel node ( a list of them exist on evernode.app ) Then you visit the frontend page (runs on gptcp1) and create a login user in the HotPocket Admin page. You create the user by conecting to hotpocket, the first time you connect you'll have the ability to create the user, after you've done that you need to connect again to log in.

After logging in you can go back to the front page and connect as head admin.

When connected as a head admin, you create your cluster wallet (or import one), you add xah to activate it, then add a trustline and send evr's to the trustline. Don't fill up with too much funds, because this wallet will only be used by the cluster, and when you are fully finished you won't be able to control it yourself as its keys will be disabled.

After that you pick a bundle of instances (make sure to have a good variety, not all at the same host) to have in the cluster, set a max lease cost (this protects you) and optionally, add additional xahau nodes (fallbacks, seperated by new lines and prioritzed by number). You can also adjust cluster size if you want. 3 signers 5 instances is a good mix though, all instances can sign but only 3 are needed for action. What they sign is extension of cluster life and replacement of instances if one dies. The cluster lives on until it runs out of fuel. Balance adjustment is activated, but it isn't still being fetched by the system, that is something to add in smart contract.

When everything is finished you just hit start autonomous bootstrap and enjoy the show. 

The last thing to do after your cluster is up and running is finalizing, that process will disable your master keys and at this point the cluster is controlled by the cluster itself through multisig.

You are free to fork, but this code has no warranties of any kind. It is hastily done and should only be used for experimentation and education.

Project: https://evernode.org 
Discord: https://discord.gg/DAQszjKEBV
