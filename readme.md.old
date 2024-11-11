🔐 Vaultwarden NixOS Configuration

## 🤔 What is this?

This is a NixOS configuration for a VPS that will host a [vaultwarden](https://github.com/dani-garcia/vaultwarden) server. It aims to provide a hardened and secure server that can be quickly installed on any provider.

## ✨ Features

- 🔄 Replace the base OS the VPS provides
- 🐧 Use NixOS BTW
- 🔀 Reverse proxy via `traefik` with automatic SSL provided by `letsencrypt`
- 🔒 Secure SSH with cleaner defaults and forcing passphrase
- 🛡️ Hardening with `fail2ban` and `waf`
- 🔄 Automatic updates with `watchtower` for the containers
- 📢 Update info via `watchtower` to a Discord Webhook

## 🚀 What could be improved

- 📁 Making the log for `waf` work on user folder for quick access
- 💾 Automatic backup to external services
- 🔑 MFA / Yubikey autosetup
- 📱 [Push update](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-Mobile-Client-push-notification)

## 📋 Requirements

- 💻 A system with Nix to deploy by NixOS-anywhere
- 🖥️ A cheap 2GB RAM VPS (it's NixOS-anywhere's requirement; I didn't test on 1GB RAM VPS)
- 🔑 An SSH key to connect to the VPS that you can store somewhere on your system
- 🌐 A domain name to point to the VPS

## 🛠️ Installation

### 1️⃣ Clone this repository (or fork it)

### 2️⃣ Edit the config.nix to match your needs

On `config.nix`:

- Replace `dylan` with your username
- Replace the SSH key with your own public key

### 3️⃣ Prepare the docker-env

Modify the `example.env` to match your needs and rename it to `.env`. The variables match the ones in the `docker-compose.yml` and those expected by the `vaultwarden` image.

> ⚠️ You need to set the SMTP parameters because vaultwarden needs it to verify your users' emails, or edit the configuration to disable it.

### 4️⃣ Set up your VPS

It should work on most types of VPS. I tested with `ionos`, but the settings I used were for Digital Ocean, and the config also handles Hetzner.

Verify if it supports cloud-init:

```bash
systemctl status cloud-init
```

You'll then know if your cloud provider uses it; most likely, it will. You only need to grab the root password for the VPS and the IP address.

### 5️⃣ Replace the pre-installed OS and set up the system

```bash
SSHPASS=password nix run --impure github:nix-community/nixos-anywhere/69ad3f4a50cfb711048f54013404762c9a8e201e -- --flake /home/dylan/repo/vault-nix#digitalocean root@ipaddress --env-password
```

> 📝 I'm using a specific commit because the current master is being refactored and is broken [GitHub Issue](https://github.com/nix-community/nixos-anywhere/issues/376)

Replace `password` with the root password of the VPS and `ipaddress` with the IP address of the VPS. The `/home/dylan/repo/vault-nix` is the path to the GitHub repo; replace this with where you cloned the repo.

This will completely replace the OS with NixOS and set up the system. If you use Hetzner, you need to replace `digitalocean` with `hetzner` in the command.

### 6️⃣ Connect to the server

Remove the entry in your `~/.ssh/known_hosts` for the IP of the VPS. Connect to it via the key you set earlier.

### 7️⃣ Set up and launch Docker

Docker is already installed and configured. The only things needed are the `docker-compose.yml` and the `.env` file. I personally use `SSHFS` to quickly do this, but you can clone the repo again on the VPS if needed (git is installed).

On the server, in the folder where the docker-compose.yml is located, run:

```bash
docker-compose up -d
# or the alias I use for it
dcu
```

Check the logs with `lazydocker`:

```bash
lazydocker
# or the alias I use for it
ld
```

## ℹ️ Additional Information

The example `.env` is configured with `VW_SIGNUPS_ALLOWED` set to true, which allows anyone to create an account on the server. The admin page is enabled too, so either disable it or secure it with a good token. Disable `VW_SIGNUP_VERIFY` if you don't want to use email verification.

## 💡 Tips

If you rely on ssh-agent to store your SSH key, you might have an issue with nixos-anywhere, so you can clear your agent of all its keys before running the setup command if needed with `ssh-add -D`.

To configure the admin token, read the `vaultwarden` [documentation](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-admin-page). If you decide to use Argon2 to secure the admin token, you can quickly use `nix-shell -p openssl libargon2` to have OpenSSL and Argon2 to generate the token and secure it further: [documentation](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-admin-page#using-argon2).

Once deployed if you want to push change to your nix system easily you can rebuild it directly from your computer:

```bash
nixos-rebuild switch --flake "/home/dylan/repo/vault-nix#digitalocean" --target-host dylan@remoteip --use-remote-sudo
```

_you can now use your `user` instead of `root` to rebuild the system`_
