{
  modulesPath,
  config,
  lib,
  pkgs,
  ...
}:
let

  # User variables
  USER_NAME = "dylan";
  USER_HOME = "/home/${USER_NAME}";
  USER_SSH_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOyJ/2kbC+IaD43k9+6UEcqn+B8BlwPYqNamEqKiBk+O ionos";

  # System variables
  MACHINE_HOSTNAME = "vaultwarden";
  SYSTEM_STATE_VERSION = "24.05";

  # Application variables
  WAF_LOG_PATH = "${USER_HOME}/waf/log/";
  DOCKER_PATH = "${USER_HOME}/docker";
  LETSENCRYPT_PATH = "${DOCKER_PATH}/letsencrypt";
  VAULTWARDEN_PATH = "${DOCKER_PATH}/vaultwarden";

  # Fail2ban variables
  FAIL2BAN_MAXRETRY = 5;
  FAIL2BAN_BANTIME = "24h";
  WAF_JAIL_MAXRETRY = 1;
  WAF_JAIL_BANTIME = "14400";
  WAF_JAIL_FINDTIME = "14400";
in
{
  #TEST: from nixos-anywhare example not certain they are needed ?
  imports = [
    (modulesPath + "/installer/scan/not-detected.nix")
    (modulesPath + "/profiles/qemu-guest.nix")
    ./disk-config.nix
  ];
  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];

  #HACK: this allow to rebuild to remote host without creating a sign key, ssh is enough for me
  nix.settings = {
    accept-flake-config = true;
    require-sigs = false;
  };
  boot.loader.grub = {
    efiSupport = true;
    efiInstallAsRemovable = true;
  };
  #NOTE: there is a direct option for this i think
  security.sudo.extraRules = [
    {
      users = [ USER_NAME ];
      commands = [
        {
          command = "ALL";
          options = [ "NOPASSWD" ];
        }
      ];
    }
  ];

  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = false;
      PermitRootLogin = "no";
      KbdInteractiveAuthentication = false;
      X11Forwarding = false;
      AuthenticationMethods = "publickey";
      UsePAM = false;
    };
    #NOTE: i need mazauth try set to 10 for my ssh agent to work on all my servers
    # still using default ssh port for now
    extraConfig = ''
      AllowUsers ${USER_NAME}
      PubkeyAuthentication yes
      AllowTcpForwarding no
      AllowAgentForwarding no
      MaxAuthTries 10
      ClientAliveCountMax 2
      MaxSessions 2
      # Port 2222  # Choose a different non-standard port
      TCPKeepAlive no
    '';
  };

  environment.systemPackages = map lib.lowPrio [
    pkgs.curl
    pkgs.gitMinimal
    pkgs.neovim
    pkgs.yazi
    pkgs.ripgrep
    pkgs.fd
    pkgs.docker
    pkgs.docker-compose
    pkgs.lazydocker
    pkgs.tailscale
    pkgs.lazydocker
    pkgs.lynis # security scanner : sudo lynis audit system
  ];
  programs.bash = {
    shellAliases = {
      n = "nvim";
      y = "yazi";
      ld = "lazydocker";
      dc = "docker compose";
      dcu = "docker compose up -d";
      dcd = "docker compose down";
    };
  };

  virtualisation.docker = {
    enable = true;
    enableOnBoot = true;
  };
  users.users.${USER_NAME} = {
    isNormalUser = true;
    extraGroups = [
      "wheel"
      "networkmanager"
      "docker"
    ];
    initialPassword = USER_NAME;
    home = USER_HOME;
    openssh.authorizedKeys.keys = [ USER_SSH_KEY ];
  };

  system.stateVersion = SYSTEM_STATE_VERSION;

  services.tailscale = {
    enable = true;
    openFirewall = true;
    interfaceName = "tailscale0";
    # authKeyFile = tailscaleAuthKeyFile;
    # TEST: does these auto tag still work?
    extraUpFlags = [
      "--hostname=${config.networking.hostName}"
      "--advertise-tags=tag:nixos,tag:server"
      "--accept-dns=true"
    ];
  };

  networking = {
    hostName = MACHINE_HOSTNAME;
    firewall = {
      trustedInterfaces = [ "tailscale0" ];
      allowedTCPPorts = [ 22 ];
    };
  };
  # Now set up the activation scripts
  system.activationScripts = {
    setupWafDirectories = {
      text = ''
        # Create waf directories
        mkdir -p ${USER_HOME}/waf/log ${USER_HOME}/waf/rules
        chown -R ${USER_NAME}:${USER_NAME} ${USER_HOME}/waf
        #FIXME: i cant make fail2ban work with logfolder in my home user , and we neeed to create the log file manually
        touch /var/log/modsec_error.log

        # Create docker directory
        mkdir -p ${DOCKER_PATH}
        chown ${USER_NAME}:${USER_NAME} ${DOCKER_PATH}
        chmod 775 ${DOCKER_PATH}

        # Create letsencrypt directory under docker
        mkdir -p ${LETSENCRYPT_PATH}
        chown ${USER_NAME}:${USER_NAME} ${LETSENCRYPT_PATH}
        chmod 775 ${LETSENCRYPT_PATH}

        # Create vaultwarden directory
        mkdir -p ${VAULTWARDEN_PATH}
        chown ${USER_NAME}:${USER_NAME} ${VAULTWARDEN_PATH}
        chmod 775 ${VAULTWARDEN_PATH}
      '';
      deps = [ ];
    };
  };

  services.fail2ban = {
    enable = true;
    # Global settings
    maxretry = FAIL2BAN_MAXRETRY;
    bantime = FAIL2BAN_BANTIME;
    jails = {
      waf.settings = {
        loglevel = "DEBUG";
        enabled = true;
        filter = "waf";
        logpath = WAF_LOG_PATH + "modsec_error.log";
        maxretry = WAF_JAIL_MAXRETRY;
        bantime = WAF_JAIL_BANTIME;
        findtime = WAF_JAIL_FINDTIME;
        backend = "auto";
      };
    };
  };

  # Define the WAF filter
  environment.etc."fail2ban/filter.d/waf.conf".text = ''
    [INCLUDES]
    before = common.conf

    [Definition]
    failregex = ^\[.*\] \[.*\] \[client <HOST>\] ModSecurity: Access denied.*$
    ignoreregex =
  '';
}
# NOTE: Generate the admin token in nix https://github.com/dani-garcia/vaultwarden/wiki/Enabling-admin-page#using-argon2 
# nix-shell -p openssl libargon2
#openssl rand -base64 48
# passs the output to :
# echo -n "MySecretPassword" | argon2 "$(openssl rand -base64 32)" -e -id -k 65540 -t 3 -p 4 | sed 's#\$#\$\$#g'
