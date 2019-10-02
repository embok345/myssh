# MySSH

MySSH is a shoddy SSH client.

##Compilation

Make sure you have the the bignum library.

```bash
git clone git://git.poulter.space/bignum.git
```

Compile (and optionally install) the bignum library.

Edit the first two lines of Makefile to point to the location of the bignum library and header file.

Then simply run make. This will place the excecutable at bin/myssh

## Usage

Connect to an SSH server by running

```bash
./myssh [user]@[server]:[port]
```

where 'user' the the user to connect to the server, 'server' is the address of the SSH server to connect to, and 'port' is the port that the SSH server is running on. 

