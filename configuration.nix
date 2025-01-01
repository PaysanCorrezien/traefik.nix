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
  USER_SSH_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINpKQ0EH2eg++vdrgbugCjeUE02qc64V6U0CxCOAdnvX dylan@cloud-auth";

  # System variables
  MACHINE_HOSTNAME = "auth";
  SYSTEM_STATE_VERSION = "24.05";

  # Application variables
  WAF_LOG_PATH = "${USER_HOME}/waf/log/";
  DOCKER_PATH = "${USER_HOME}/docker";
  LETSENCRYPT_PATH = "${DOCKER_PATH}/letsencrypt";
  OPENLDAP_PATH = "${DOCKER_PATH}/openldap";
  AUTHELIA_PATH = "${DOCKER_PATH}/authelia";
  HOMEPAGE_PATH = "${DOCKER_PATH}/homepage";

  # Fail2ban variables
  FAIL2BAN_MAXRETRY = 5;
  FAIL2BAN_BANTIME = "24h";
  WAF_JAIL_MAXRETRY = 1;
  WAF_JAIL_BANTIME = "14400";
  WAF_JAIL_FINDTIME = "14400";
in
{
  imports = [
    (modulesPath + "/installer/scan/not-detected.nix")
    (modulesPath + "/profiles/qemu-guest.nix")
    ./disk-config.nix
    (fetchTarball "https://github.com/nix-community/nixos-vscode-server/tarball/master")
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
      #for vs code
      AllowTcpForwarding yes
      AllowAgentForwarding no
      MaxAuthTries 10
      ClientAliveCountMax 2
      MaxSessions 2
      # Port 2222  # Choose a different non-standard port
      TCPKeepAlive yes
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
      dk = "lazydocker";
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
    useRoutingFeatures = "both"; # Enables routing features
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

  #TODO: fix tis is cant be dylan:dylan for chown
  # Add this section to your configuration
  systemd.tmpfiles.rules = [
    # Main docker directory
    "d ${DOCKER_PATH} 0775 ${USER_NAME} users -"

    # WAF directories
    "d ${USER_HOME}/waf 0775 ${USER_NAME} users -"
    "d ${USER_HOME}/waf/log 0775 ${USER_NAME} users -"
    "d ${USER_HOME}/waf/rules 0775 ${USER_NAME} users -"
    "f /var/log/modsec_error.log 0664 ${USER_NAME} users -"

    # Service directories
    "d ${LETSENCRYPT_PATH} 0775 ${USER_NAME} users -"
    "d ${OPENLDAP_PATH} 0775 ${USER_NAME} users -"
    "d ${OPENLDAP_PATH}/data 0775 ${USER_NAME} users -"
    "d ${OPENLDAP_PATH}/config 0775 ${USER_NAME} users -"
    "d ${AUTHELIA_PATH} 0775 ${USER_NAME} users -"
    "d ${HOMEPAGE_PATH} 0775 ${USER_NAME} users -"
  ];

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

  environment.etc."fail2ban/filter.d/waf.conf".text = ''
    [INCLUDES]
    before = common.conf

    [Definition]
    failregex = ^\[.*\] \[.*\] \[client <HOST>\] ModSecurity: Access denied.*$
    ignoreregex =
  '';

  boot.kernel.sysctl = {
    "net.ipv4.ip_forward" = 1;
    "net.ipv6.conf.all.forwarding" = 1;
  };

  systemd.services.ethtool-config = {
    description = "Configure network interface optimizations";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = "yes";
      ExecStart = "${pkgs.ethtool}/bin/ethtool -K ens6 rx-udp-gro-forwarding on";
    };
  };
  services.vscode-server.enable = true;

}

