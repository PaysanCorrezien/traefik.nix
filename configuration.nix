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
  MACHINE_HOSTNAME = "homeserver";
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
  ];

  # Rest of the configuration remains the same as before...

  system.activationScripts = {
    setupDirectories = {
      text = ''
        # Create waf directories
        mkdir -p ${USER_HOME}/waf/log ${USER_HOME}/waf/rules
        chown -R ${USER_NAME}:${USER_NAME} ${USER_HOME}/waf
        touch /var/log/modsec_error.log

        # Create docker directory
        mkdir -p ${DOCKER_PATH}
        chown ${USER_NAME}:${USER_NAME} ${DOCKER_PATH}
        chmod 775 ${DOCKER_PATH}

        # Create letsencrypt directory
        mkdir -p ${LETSENCRYPT_PATH}
        chown ${USER_NAME}:${USER_NAME} ${LETSENCRYPT_PATH}
        chmod 775 ${LETSENCRYPT_PATH}

        # Create OpenLDAP directory
        mkdir -p ${OPENLDAP_PATH}/data ${OPENLDAP_PATH}/config
        chown ${USER_NAME}:${USER_NAME} ${OPENLDAP_PATH}
        chmod 775 ${OPENLDAP_PATH}

        # Create Authelia directory
        mkdir -p ${AUTHELIA_PATH}
        chown ${USER_NAME}:${USER_NAME} ${AUTHELIA_PATH}
        chmod 775 ${AUTHELIA_PATH}

        # Create Homepage directory
        mkdir -p ${HOMEPAGE_PATH}
        chown ${USER_NAME}:${USER_NAME} ${HOMEPAGE_PATH}
        chmod 775 ${HOMEPAGE_PATH}
      '';
      deps = [ ];
    };
  };

  # Rest of the configuration remains the same...
}
