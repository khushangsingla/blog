---
title: "Coffre: The Insecure Vault"
last_modified_at: 2024-07-20
categories:
  - Blog
tags:
  - Coffre
  - Cybersecurity
  - Attacks
---

In previous semester, I had a course of Implementation of Programming Languages.
The lab assignments of the course were to be done in Coffre, a "secure vault" that
prevents sharing code, copy-pasting from internet, using GPT etc. The only way
to copy from internet was to read and type the code alongside, a thing that can
never be prevented for a home assignment. I and [Hrishikesh](https://hrishi-06.github.io/)
were in a team.

We decided to find out how it prevents cheating and ended up finding various
ways to break into the vault. Here, I discuss our findings. These were reported
to [Prof. Uday Khedker](https://www.cse.iitb.ac.in/~uday/) before being written
about here.

## Background of Coffre

Coffre is a secure vault to prevent cheating. A disk image is shared with students
which is to be booted in VirtualBox. This image then sets up coffre in a virtualbox.
After the setup, we have an ubuntu 22.04 OS running. Here is some information about it.

- We have access to a user corresponding to our group.
- There is a firewall enabled which allows only outbound connections to `coffre server`
- The `coffre server` has a git server set up along with a submission setup.
- We use `moodle` command to submit our assignments on the server.
- No copy-pasting is allowed from outside the virtual machine.
- Disk image is encrypted which is decrypted at boot time.
- This decryption key is recieved from another server using an HTTPS connection.

## Breaking Coffre

### Using unencrypted partition

We found out that it mounts the boot partition and the boot partition is neither
encrypted nor it has any r/w restrictions. This allowed us to copy files into and
out of "the secure vault".

We used it to copy our configuration files for editor into coffre and reported it.
Later, the r/w permission for the mount was removed, preventing this attack.

### Decrypting the encrypted disk

Next came a thought, what if we pause the virtual machine instead of powering it
off. There should be some way to get the decrypted disk.

We searched a bit and found that the disk decryption key is loaded in RAM at boot.
This key is used to decrypt the blocks of disk as the disk is read. We took a dump
of RAM. Using the tool [findaes](https://sourceforge.net/projects/findaes/), we were
able to extract the AES keys from the RAM dump. Using this key, we were able to
decrypt the disk and mount it in our own OS. This allowed us to access the disk
without any restrictions.

#### Extracting git server access

We found out that "the secure vault" used a patched ssh binary to access server.
It used a key whose password was hardcoded in the patched binary. We recovered
this password from the ssh binary and got the access to the git server from
outside.

### Accessing the submission server

Once, we did a wrong submission and an error appeared. The error talked about
connnecting to submission server over ssh and the rest of the error seemed as
if it was returned by server. We then read the submission script in `moodle.py`,
the file behind the `moodle` command we used for submissions. This script did
ssh into submission server and added some parameters. We realised that instead
of getting a shell, the server runs a script based on the arguments. After some
hit and trial, we were able to run custom commands on the server and get the
`stderr` as output.

We used this to print the server side script and found out that the server was
feeding our input directly as an argument to `os.system`, which allowed us to
run commands on server. This command injection allowed us to edit/retrieve anyone's
submissions.

We stopped at it as now, we were able to access even the server. It was fun
to find out various important and small points that were taken care of while
creating "the secure vault", which was no more secure because of missing a few
intricacies, the biggest of which was command injection on server. Servers
need to be made considering any kind of input from the clients, not just the
expected inputs. That's the best way to make servers secure I believe. The
decryption of disk part seems to be a tough problem to solve as the requirement
is that the virtual machine be running on user's machine. It may be made tough
by not using standard encryption, using multiple layers of encryption, etc.