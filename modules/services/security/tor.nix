{ config, lib, options, pkgs, ... }:

with builtins;
with lib;

let
  cfg = config.services.tor;
  opt = options.services.tor;
  stateDir = "/var/lib/tor";
  runDir = "/run/tor";
  descriptionGeneric = option: ''
    See [torrc manual](https://2019.www.torproject.org/docs/tor-manual.html.en#${option}).
  '';
  bindsPrivilegedPort =
    any (p0:
      let p1 = if p0 ? "port" then p0.port else p0; in
      if p1 == "auto" then false
      else let p2 = if isInt p1 then p1 else toInt p1; in
        p1 != null && 0 < p2 && p2 < 1024)
    (flatten [
      cfg.settings.ORPort
      cfg.settings.DirPort
      cfg.settings.DNSPort
      cfg.settings.ExtORPort
      cfg.settings.HTTPTunnelPort
      cfg.settings.NATDPort
      cfg.settings.SOCKSPort
      cfg.settings.TransPort
    ]);
  optionBool = optionName: mkOption {
    type = with types; nullOr bool;
    default = null;
    description = lib.mdDoc (descriptionGeneric optionName);
  };
  optionInt = optionName: mkOption {
    type = with types; nullOr int;
    default = null;
    description = lib.mdDoc (descriptionGeneric optionName);
  };
  optionString = optionName: mkOption {
    type = with types; nullOr str;
    default = null;
    description = lib.mdDoc (descriptionGeneric optionName);
  };
  optionStrings = optionName: mkOption {
    type = with types; listOf str;
    default = [];
    description = lib.mdDoc (descriptionGeneric optionName);
  };
  optionAddress = mkOption {
    type = with types; nullOr str;
    default = null;
    example = "0.0.0.0";
    description = lib.mdDoc ''
      IPv4 or IPv6 (if between brackets) address.
    '';
  };
  optionUnix = mkOption {
    type = with types; nullOr path;
    default = null;
    description = lib.mdDoc ''
      Unix domain socket path to use.
    '';
  };
  optionPort = mkOption {
    type = with types; nullOr (oneOf [port (enum ["auto"])]);
    default = null;
  };
  optionPorts = optionName: mkOption {
    type = with types; listOf port;
    default = [];
    description = lib.mdDoc (descriptionGeneric optionName);
  };
  optionIsolablePort = with types; oneOf [
    port (enum ["auto"])
    (submodule ({config, ...}: {
      options = {
        addr = optionAddress;
        port = optionPort;
        flags = optionFlags;
        SessionGroup = mkOption { type = nullOr int; default = null; };
      } // genAttrs isolateFlags (name: mkOption { type = types.bool; default = false; });
      config = {
        flags = filter (name: config.${name} == true) isolateFlags ++
                optional (config.SessionGroup != null) "SessionGroup=${toString config.SessionGroup}";
      };
    }))
  ];
  optionIsolablePorts = optionName: mkOption {
    default = [];
    type = with types; either optionIsolablePort (listOf optionIsolablePort);
    description = lib.mdDoc (descriptionGeneric optionName);
  };
  isolateFlags = [
    "IsolateClientAddr"
    "IsolateClientProtocol"
    "IsolateDestAddr"
    "IsolateDestPort"
    "IsolateSOCKSAuth"
    "KeepAliveIsolateSOCKSAuth"
  ];
  optionSOCKSPort = doConfig: let
    flags = [
      "CacheDNS" "CacheIPv4DNS" "CacheIPv6DNS" "GroupWritable" "IPv6Traffic"
      "NoDNSRequest" "NoIPv4Traffic" "NoOnionTraffic" "OnionTrafficOnly"
      "PreferIPv6" "PreferIPv6Automap" "PreferSOCKSNoAuth" "UseDNSCache"
      "UseIPv4Cache" "UseIPv6Cache" "WorldWritable"
    ] ++ isolateFlags;
    in with types; oneOf [
      port (submodule ({config, ...}: {
        options = {
          unix = optionUnix;
          addr = optionAddress;
          port = optionPort;
          flags = optionFlags;
          SessionGroup = mkOption { type = nullOr int; default = null; };
        } // genAttrs flags (name: mkOption { type = types.bool; default = false; });
        config = mkIf doConfig { # Only add flags in SOCKSPort to avoid duplicates
          flags = filter (name: config.${name} == true) flags ++
                  optional (config.SessionGroup != null) "SessionGroup=${toString config.SessionGroup}";
        };
      }))
    ];
  optionFlags = mkOption {
    type = with types; listOf str;
    default = [];
  };
  optionORPort = optionName: mkOption {
    default = [];
    example = 443;
    type = with types; oneOf [port (enum ["auto"]) (listOf (oneOf [
      port
      (enum ["auto"])
      (submodule ({config, ...}:
        let flags = [ "IPv4Only" "IPv6Only" "NoAdvertise" "NoListen" ];
        in {
        options = {
          addr = optionAddress;
          port = optionPort;
          flags = optionFlags;
        } // genAttrs flags (name: mkOption { type = types.bool; default = false; });
        config = {
          flags = filter (name: config.${name} == true) flags;
        };
      }))
    ]))];
    description = lib.mdDoc (descriptionGeneric optionName);
  };
  optionBandwidth = optionName: mkOption {
    type = with types; nullOr (either int str);
    default = null;
    description = lib.mdDoc (descriptionGeneric optionName);
  };
  optionPath = optionName: mkOption {
    type = with types; nullOr path;
    default = null;
    description = lib.mdDoc (descriptionGeneric optionName);
  };

  mkValueString = k: v:
    if v == null then ""
    else if isBool v then
      (if v then "1" else "0")
    else if v ? "unix" && v.unix != null then
      "unix:"+v.unix +
      optionalString (v ? "flags") (" " + concatStringsSep " " v.flags)
    else if v ? "port" && v.port != null then
      optionalString (v ? "addr" && v.addr != null) "${v.addr}:" +
      toString v.port +
      optionalString (v ? "flags") (" " + concatStringsSep " " v.flags)
    else if k == "ServerTransportPlugin" then
      optionalString (v.transports != []) "${concatStringsSep "," v.transports} exec ${v.exec}"
    else if k == "HidServAuth" then
      v.onion + " " + v.auth
    else generators.mkValueStringDefault {} v;
  genTorrc = settings:
    generators.toKeyValue {
      listsAsDuplicateKeys = true;
      mkKeyValue = k: generators.mkKeyValueDefault { mkValueString = mkValueString k; } " " k;
    }
    (lib.mapAttrs (k: v:
      # Not necesssary, but prettier rendering
      if elem k [ "AutomapHostsSuffixes" "DirPolicy" "ExitPolicy" "SocksPolicy" ]
      && v != []
      then concatStringsSep "," v
      else v)
    (lib.filterAttrs (k: v: !(v == null || v == ""))
    settings));
  torrc = pkgs.writeText "torrc" (
    genTorrc cfg.settings +
    concatStrings (mapAttrsToList (name: onion:
      "HiddenServiceDir ${onion.path}\n" +
      genTorrc onion.settings) cfg.relay.onionServices)
  );
in
{
  imports = [
    (mkRenamedOptionModule [ "services" "tor" "client" "dns" "automapHostsSuffixes" ] [ "services" "tor" "settings" "AutomapHostsSuffixes" ])
    (mkRemovedOptionModule [ "services" "tor" "client" "dns" "isolationOptions" ] "Use services.tor.settings.DNSPort instead.")
    (mkRemovedOptionModule [ "services" "tor" "client" "dns" "listenAddress" ] "Use services.tor.settings.DNSPort instead.")
    (mkRemovedOptionModule [ "services" "tor" "client" "privoxy" "enable" ] "Use services.privoxy.enable and services.privoxy.enableTor instead.")
    (mkRemovedOptionModule [ "services" "tor" "client" "socksIsolationOptions" ] "Use services.tor.settings.SOCKSPort instead.")
    (mkRemovedOptionModule [ "services" "tor" "client" "socksListenAddressFaster" ] "Use services.tor.settings.SOCKSPort instead.")
    (mkRenamedOptionModule [ "services" "tor" "client" "socksPolicy" ] [ "services" "tor" "settings" "SocksPolicy" ])
    (mkRemovedOptionModule [ "services" "tor" "client" "transparentProxy" "isolationOptions" ] "Use services.tor.settings.TransPort instead.")
    (mkRemovedOptionModule [ "services" "tor" "client" "transparentProxy" "listenAddress" ] "Use services.tor.settings.TransPort instead.")
    (mkRenamedOptionModule [ "services" "tor" "controlPort" ] [ "services" "tor" "settings" "ControlPort" ])
    (mkRemovedOptionModule [ "services" "tor" "extraConfig" ] "Please use services.tor.settings instead.")
    (mkRenamedOptionModule [ "services" "tor" "hiddenServices" ] [ "services" "tor" "relay" "onionServices" ])
    (mkRenamedOptionModule [ "services" "tor" "relay" "accountingMax" ] [ "services" "tor" "settings" "AccountingMax" ])
    (mkRenamedOptionModule [ "services" "tor" "relay" "accountingStart" ] [ "services" "tor" "settings" "AccountingStart" ])
    (mkRenamedOptionModule [ "services" "tor" "relay" "address" ] [ "services" "tor" "settings" "Address" ])
    (mkRenamedOptionModule [ "services" "tor" "relay" "bandwidthBurst" ] [ "services" "tor" "settings" "BandwidthBurst" ])
    (mkRenamedOptionModule [ "services" "tor" "relay" "bandwidthRate" ] [ "services" "tor" "settings" "BandwidthRate" ])
    (mkRenamedOptionModule [ "services" "tor" "relay" "bridgeTransports" ] [ "services" "tor" "settings" "ServerTransportPlugin" "transports" ])
    (mkRenamedOptionModule [ "services" "tor" "relay" "contactInfo" ] [ "services" "tor" "settings" "ContactInfo" ])
    (mkRenamedOptionModule [ "services" "tor" "relay" "exitPolicy" ] [ "services" "tor" "settings" "ExitPolicy" ])
    (mkRemovedOptionModule [ "services" "tor" "relay" "isBridge" ] "Use services.tor.relay.role instead.")
    (mkRemovedOptionModule [ "services" "tor" "relay" "isExit" ] "Use services.tor.relay.role instead.")
    (mkRenamedOptionModule [ "services" "tor" "relay" "nickname" ] [ "services" "tor" "settings" "Nickname" ])
    (mkRenamedOptionModule [ "services" "tor" "relay" "port" ] [ "services" "tor" "settings" "ORPort" ])
    (mkRenamedOptionModule [ "services" "tor" "relay" "portSpec" ] [ "services" "tor" "settings" "ORPort" ])
  ];

  options = {
    services.tor = {
      enable = mkEnableOption (lib.mdDoc ''Tor daemon.
        By default, the daemon is run without
        relay, exit, bridge or client connectivity'');

      hideWarningSeparateTorProcess = mkOption {
        type = types.bool;
        default = false;
        description = lib.mdDoc ''
          Hide the warning when running relay and hidden services
          in the same Tor process.
        '';
      };

      openFirewall = mkEnableOption (lib.mdDoc "opening of the relay port(s) in the firewall");

      package = mkPackageOption pkgs "tor" { };

      enableGeoIP = mkEnableOption (lib.mdDoc ''use of GeoIP databases.
        Disabling this will disable by-country statistics for bridges and relays
        and some client and third-party software functionality'') // { default = true; };

      controlSocket.enable = mkEnableOption (lib.mdDoc ''control socket,
        created in `${runDir}/control`'');

      client = {
        enable = mkEnableOption (lib.mdDoc ''the routing of application connections.
          You might want to disable this if you plan running a dedicated Tor relay'');

        transparentProxy.enable = mkEnableOption (lib.mdDoc "transparent tor proxy");
        dns.enable = mkEnableOption (lib.mdDoc "DNS resolver");

        transparentProxy.routeAllTraffic = mkEnableOption (lib.mdDoc ''
          Route all network traffic through the Tor transparent proxy
        '');

        transparentProxy.externalInterface = mkOption {
          type = with types; nullOr str;
          default = null;
          # TODO require if transparentProxy.routeAllTraffic
          description = lib.mdDoc ''
            Tor will use this network interface
            to connect to the internet
          '';
        };

        transparentProxy.allowSubnets = mkOption {
          type = with types; listOf str;
          default = [
            "127.0.0.0/8"
            "10.0.0.0/8"
            "172.16.0.0/12"
            "192.168.0.0/16"
          ];
          description = lib.mdDoc ''
            Allow access to these subnets
            without routing the traffic through Tor.

            LAN destinations that shouldn't be routed through Tor.
          '';
        };

        transparentProxy.blockSubnets = mkOption {
          type = with types; listOf str;
          default = [
            "0.0.0.0/8"
            "100.64.0.0/10"
            "169.254.0.0/16"
            "192.0.0.0/24"
            "192.0.2.0/24"
            "192.88.99.0/24"
            "198.18.0.0/15"
            "198.51.100.0/24"
            "203.0.113.0/24"
            "224.0.0.0/4"
            "240.0.0.0/4"
            "255.255.255.255/32" # isnt that everything...?
          ];
          description = lib.mdDoc ''
            Block all access to these subnets.
            IANA reserved blocks.
            These are not processed by Tor and dropped by default.
          '';
        };

        socksListenAddress = mkOption {
          type = optionSOCKSPort false;
          default = {addr = "127.0.0.1"; port = 9050; IsolateDestAddr = true;};
          example = {addr = "192.168.0.1"; port = 9090; IsolateDestAddr = true;};
          description = lib.mdDoc ''
            Bind to this address to listen for connections from
            Socks-speaking applications.
          '';
        };

        onionServices = mkOption {
          description = lib.mdDoc (descriptionGeneric "HiddenServiceDir");
          default = {};
          example = {
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" = {
              clientAuthorizations = ["/run/keys/tor/alice.prv.x25519"];
            };
          };
          type = types.attrsOf (types.submodule ({name, config, ...}: {
            options.clientAuthorizations = mkOption {
              description = lib.mdDoc ''
                Clients' authorizations for a v3 onion service,
                as a list of files containing each one private key, in the format:
                ```
                descriptor:x25519:<base32-private-key>
                ```
                ${descriptionGeneric "_client_authorization"}
              '';
              type = with types; listOf path;
              default = [];
              example = ["/run/keys/tor/alice.prv.x25519"];
            };
          }));
        };
      };

      relay = {
        enable = mkEnableOption (lib.mdDoc "tor relaying") // {
          description = lib.mdDoc ''
            Whether to enable relaying of Tor traffic for others.

            See <https://www.torproject.org/docs/tor-doc-relay>
            for details.

            Setting this to true requires setting
            {option}`services.tor.relay.role`
            and
            {option}`services.tor.settings.ORPort`
            options.
          '';
        };

        role = mkOption {
          type = types.enum [ "exit" "relay" "bridge" "private-bridge" ];
          description = lib.mdDoc ''
            Your role in Tor network. There're several options:

            - `exit`:
              An exit relay. This allows Tor users to access regular
              Internet services through your public IP.

              You can specify which services Tor users may access via
              your exit relay using {option}`settings.ExitPolicy` option.

            - `relay`:
              Regular relay. This allows Tor users to relay onion
              traffic to other Tor nodes, but not to public
              Internet.

              See
              <https://www.torproject.org/docs/tor-doc-relay.html.en>
              for more info.

            - `bridge`:
              Regular bridge. Works like a regular relay, but
              doesn't list you in the public relay directory and
              hides your Tor node behind obfs4proxy.

              Using this option will make Tor advertise your bridge
              to users through various mechanisms like
              <https://bridges.torproject.org/>, though.

              See <https://www.torproject.org/docs/bridges.html.en>
              for more info.

            - `private-bridge`:
              Private bridge. Works like regular bridge, but does
              not advertise your node in any way.

              Using this role means that you won't contribute to Tor
              network in any way unless you advertise your node
              yourself in some way.

              Use this if you want to run a private bridge, for
              example because you'll give out your bridge addr
              manually to your friends.

              Switching to this role after measurable time in
              "bridge" role is pretty useless as some Tor users
              would have learned about your node already. In the
              latter case you can still change
              {option}`port` option.

              See <https://www.torproject.org/docs/bridges.html.en>
              for more info.

            ::: {.important}
            Running an exit relay may expose you to abuse
            complaints. See
            <https://www.torproject.org/faq.html.en#ExitPolicies>
            for more info.
            :::

            ::: {.important}
            Note that some misconfigured and/or disrespectful
            towards privacy sites will block you even if your
            relay is not an exit relay. That is, just being listed
            in a public relay directory can have unwanted
            consequences.

            Which means you might not want to use
            this role if you browse public Internet from the same
            network as your relay, unless you want to write
            e-mails to those sites (you should!).
            :::

            ::: {.important}
            WARNING: THE FOLLOWING PARAGRAPH IS NOT LEGAL ADVICE.
            Consult with your lawyer when in doubt.

            The `bridge` role should be safe to use in most situations
            (unless the act of forwarding traffic for others is
            a punishable offence under your local laws, which
            would be pretty insane as it would make ISP illegal).
            :::
          '';
        };

        onionServices = mkOption {
          description = lib.mdDoc (descriptionGeneric "HiddenServiceDir");
          default = {};
          example = {
            "example.org/www" = {
              map = [ 80 ];
              authorizedClients = [
                "descriptor:x25519:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
              ];
            };
          };
          type = types.attrsOf (types.submodule ({name, config, ...}: {
            options.useSeparateTorProcess = mkOption {
              type = types.bool;
              default = false;
              description = lib.mdDoc ''
                Run this hidden service in a separate Tor process.
              '';
            };
            options.path = mkOption {
              type = types.path;
              description = lib.mdDoc ''
                Path where to store the data files of the hidden service.
                If the {option}`secretKey` is null
                this defaults to `${stateDir}/onion/$onion`,
                otherwise to `${runDir}/onion/$onion`.
              '';
            };
            options.secretKey = mkOption {
              type = with types; nullOr path;
              default = null;
              example = "/run/keys/tor/onion/expyuzz4wqqyqhjn/hs_ed25519_secret_key";
              description = lib.mdDoc ''
                Secret key of the onion service.
                If null, Tor reuses any preexisting secret key (in {option}`path`)
                or generates a new one.
                The associated public key and hostname are deterministically regenerated
                from this file if they do not exist.
              '';
            };
            options.authorizeClient = mkOption {
              description = lib.mdDoc (descriptionGeneric "HiddenServiceAuthorizeClient");
              default = null;
              type = types.nullOr (types.submodule ({...}: {
                options = {
                  authType = mkOption {
                    type = types.enum [ "basic" "stealth" ];
                    description = lib.mdDoc ''
                      Either `"basic"` for a general-purpose authorization protocol
                      or `"stealth"` for a less scalable protocol
                      that also hides service activity from unauthorized clients.
                    '';
                  };
                  clientNames = mkOption {
                    type = with types; nonEmptyListOf (strMatching "[A-Za-z0-9+-_]+");
                    description = lib.mdDoc ''
                      Only clients that are listed here are authorized to access the hidden service.
                      Generated authorization data can be found in {file}`${stateDir}/onion/$name/hostname`.
                      Clients need to put this authorization data in their configuration file using
                      [](#opt-services.tor.settings.HidServAuth).
                    '';
                  };
                };
              }));
            };
            options.authorizedClients = mkOption {
              description = lib.mdDoc ''
                Authorized clients for a v3 onion service,
                as a list of public key, in the format:
                ```
                descriptor:x25519:<base32-public-key>
                ```
                ${descriptionGeneric "_client_authorization"}
              '';
              type = with types; listOf str;
              default = [];
              example = ["descriptor:x25519:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"];
            };
            options.map = mkOption {
              description = lib.mdDoc (descriptionGeneric "HiddenServicePort");
              type = with types; listOf (oneOf [
                port (submodule ({...}: {
                  options = {
                    port = optionPort;
                    target = mkOption {
                      default = null;
                      type = nullOr (submodule ({...}: {
                        options = {
                          unix = optionUnix;
                          addr = optionAddress;
                          port = optionPort;
                        };
                      }));
                    };
                  };
                }))
              ]);
              apply = map (v: if isInt v then {port=v; target=null;} else v);
            };
            options.version = mkOption {
              description = lib.mdDoc (descriptionGeneric "HiddenServiceVersion");
              type = with types; nullOr (enum [2 3]);
              default = null;
            };
            options.settings = mkOption {
              description = lib.mdDoc ''
                Settings of the onion service.
                ${descriptionGeneric "_hidden_service_options"}
              '';
              default = {};
              type = types.submodule {
                freeformType = with types;
                  (attrsOf (nullOr (oneOf [str int bool (listOf str)]))) // {
                    description = "settings option";
                  };
                options.HiddenServiceAllowUnknownPorts = optionBool "HiddenServiceAllowUnknownPorts";
                options.HiddenServiceDirGroupReadable = optionBool "HiddenServiceDirGroupReadable";
                options.HiddenServiceExportCircuitID = mkOption {
                  description = lib.mdDoc (descriptionGeneric "HiddenServiceExportCircuitID");
                  type = with types; nullOr (enum ["haproxy"]);
                  default = null;
                };
                options.HiddenServiceMaxStreams = mkOption {
                  description = lib.mdDoc (descriptionGeneric "HiddenServiceMaxStreams");
                  type = with types; nullOr (ints.between 0 65535);
                  default = null;
                };
                options.HiddenServiceMaxStreamsCloseCircuit = optionBool "HiddenServiceMaxStreamsCloseCircuit";
                options.HiddenServiceNumIntroductionPoints = mkOption {
                  description = lib.mdDoc (descriptionGeneric "HiddenServiceNumIntroductionPoints");
                  type = with types; nullOr (ints.between 0 20);
                  default = null;
                };
                options.HiddenServiceSingleHopMode = optionBool "HiddenServiceSingleHopMode";
                options.RendPostPeriod = optionString "RendPostPeriod";
              };
            };
            config = {
              path = mkDefault ((if config.secretKey == null then stateDir else runDir) + "/onion/${name}");
              settings.HiddenServiceVersion = config.version;
              settings.HiddenServiceAuthorizeClient =
                if config.authorizeClient != null then
                  config.authorizeClient.authType + " " +
                  concatStringsSep "," config.authorizeClient.clientNames
                else null;
              settings.HiddenServicePort = map (p: mkValueString "" p.port + " " + mkValueString "" p.target) config.map;
            };
          }));
        };
      };

      settings = mkOption {
        description = lib.mdDoc ''
          See [torrc manual](https://2019.www.torproject.org/docs/tor-manual.html.en)
          for documentation.
        '';
        default = {};
        type = types.submodule {
          freeformType = with types;
            (attrsOf (nullOr (oneOf [str int bool (listOf str)]))) // {
              description = "settings option";
            };
          options.Address = optionString "Address";
          options.AssumeReachable = optionBool "AssumeReachable";
          options.AccountingMax = optionBandwidth "AccountingMax";
          options.AccountingStart = optionString "AccountingStart";
          options.AuthDirHasIPv6Connectivity = optionBool "AuthDirHasIPv6Connectivity";
          options.AuthDirListBadExits = optionBool "AuthDirListBadExits";
          options.AuthDirPinKeys = optionBool "AuthDirPinKeys";
          options.AuthDirSharedRandomness = optionBool "AuthDirSharedRandomness";
          options.AuthDirTestEd25519LinkKeys = optionBool "AuthDirTestEd25519LinkKeys";
          options.AuthoritativeDirectory = optionBool "AuthoritativeDirectory";
          options.AutomapHostsOnResolve = optionBool "AutomapHostsOnResolve";
          options.AutomapHostsSuffixes = optionStrings "AutomapHostsSuffixes" // {
            default = [".onion" ".exit"];
            example = [".onion"];
          };
          options.BandwidthBurst = optionBandwidth "BandwidthBurst";
          options.BandwidthRate = optionBandwidth "BandwidthRate";
          options.BridgeAuthoritativeDir = optionBool "BridgeAuthoritativeDir";
          options.BridgeRecordUsageByCountry = optionBool "BridgeRecordUsageByCountry";
          options.BridgeRelay = optionBool "BridgeRelay" // { default = false; };
          options.CacheDirectory = optionPath "CacheDirectory";
          options.CacheDirectoryGroupReadable = optionBool "CacheDirectoryGroupReadable"; # default is null and like "auto"
          options.CellStatistics = optionBool "CellStatistics";
          options.ClientAutoIPv6ORPort = optionBool "ClientAutoIPv6ORPort";
          options.ClientDNSRejectInternalAddresses = optionBool "ClientDNSRejectInternalAddresses";
          options.ClientOnionAuthDir = mkOption {
            description = lib.mdDoc (descriptionGeneric "ClientOnionAuthDir");
            default = null;
            type = with types; nullOr path;
          };
          options.ClientPreferIPv6DirPort = optionBool "ClientPreferIPv6DirPort"; # default is null and like "auto"
          options.ClientPreferIPv6ORPort = optionBool "ClientPreferIPv6ORPort"; # default is null and like "auto"
          options.ClientRejectInternalAddresses = optionBool "ClientRejectInternalAddresses";
          options.ClientUseIPv4 = optionBool "ClientUseIPv4";
          options.ClientUseIPv6 = optionBool "ClientUseIPv6";
          options.ConnDirectionStatistics = optionBool "ConnDirectionStatistics";
          options.ConstrainedSockets = optionBool "ConstrainedSockets";
          options.ContactInfo = optionString "ContactInfo";
          options.ControlPort = mkOption rec {
            description = lib.mdDoc (descriptionGeneric "ControlPort");
            default = [];
            example = [{port = 9051;}];
            type = with types; oneOf [port (enum ["auto"]) (listOf (oneOf [
              port (enum ["auto"]) (submodule ({config, ...}: let
                flags = ["GroupWritable" "RelaxDirModeCheck" "WorldWritable"];
                in {
                options = {
                  unix = optionUnix;
                  flags = optionFlags;
                  addr = optionAddress;
                  port = optionPort;
                } // genAttrs flags (name: mkOption { type = types.bool; default = false; });
                config = {
                  flags = filter (name: config.${name} == true) flags;
                };
              }))
            ]))];
          };
          options.ControlPortFileGroupReadable= optionBool "ControlPortFileGroupReadable";
          options.ControlPortWriteToFile = optionPath "ControlPortWriteToFile";
          options.ControlSocket = optionPath "ControlSocket";
          options.ControlSocketsGroupWritable = optionBool "ControlSocketsGroupWritable";
          options.CookieAuthFile = optionPath "CookieAuthFile";
          options.CookieAuthFileGroupReadable = optionBool "CookieAuthFileGroupReadable";
          options.CookieAuthentication = optionBool "CookieAuthentication";
          options.DataDirectory = optionPath "DataDirectory" // { default = stateDir; };
          options.DataDirectoryGroupReadable = optionBool "DataDirectoryGroupReadable";
          options.DirPortFrontPage = optionPath "DirPortFrontPage";
          options.DirAllowPrivateAddresses = optionBool "DirAllowPrivateAddresses";
          options.DormantCanceledByStartup = optionBool "DormantCanceledByStartup";
          options.DormantOnFirstStartup = optionBool "DormantOnFirstStartup";
          options.DormantTimeoutDisabledByIdleStreams = optionBool "DormantTimeoutDisabledByIdleStreams";
          options.DirCache = optionBool "DirCache";
          options.DirPolicy = mkOption {
            description = lib.mdDoc (descriptionGeneric "DirPolicy");
            type = with types; listOf str;
            default = [];
            example = ["accept *:*"];
          };
          options.DirPort = optionORPort "DirPort";
          options.DirReqStatistics = optionBool "DirReqStatistics";
          options.DisableAllSwap = optionBool "DisableAllSwap";
          options.DisableDebuggerAttachment = optionBool "DisableDebuggerAttachment";
          options.DisableNetwork = optionBool "DisableNetwork";
          options.DisableOOSCheck = optionBool "DisableOOSCheck";
          options.DNSPort = optionIsolablePorts "DNSPort";
          options.DoSCircuitCreationEnabled = optionBool "DoSCircuitCreationEnabled";
          options.DoSConnectionEnabled = optionBool "DoSConnectionEnabled"; # default is null and like "auto"
          options.DoSRefuseSingleHopClientRendezvous = optionBool "DoSRefuseSingleHopClientRendezvous";
          options.DownloadExtraInfo = optionBool "DownloadExtraInfo";
          options.EnforceDistinctSubnets = optionBool "EnforceDistinctSubnets";
          options.EntryStatistics = optionBool "EntryStatistics";
          options.ExitPolicy = optionStrings "ExitPolicy" // {
            default = ["reject *:*"];
            example = ["accept *:*"];
          };
          options.ExitPolicyRejectLocalInterfaces = optionBool "ExitPolicyRejectLocalInterfaces";
          options.ExitPolicyRejectPrivate = optionBool "ExitPolicyRejectPrivate";
          options.ExitPortStatistics = optionBool "ExitPortStatistics";
          options.ExitRelay = optionBool "ExitRelay"; # default is null and like "auto"
          options.ExtORPort = mkOption {
            description = lib.mdDoc (descriptionGeneric "ExtORPort");
            default = null;
            type = with types; nullOr (oneOf [
              port (enum ["auto"]) (submodule ({...}: {
                options = {
                  addr = optionAddress;
                  port = optionPort;
                };
              }))
            ]);
            apply = p: if isInt p || isString p then { port = p; } else p;
          };
          options.ExtORPortCookieAuthFile = optionPath "ExtORPortCookieAuthFile";
          options.ExtORPortCookieAuthFileGroupReadable = optionBool "ExtORPortCookieAuthFileGroupReadable";
          options.ExtendAllowPrivateAddresses = optionBool "ExtendAllowPrivateAddresses";
          options.ExtraInfoStatistics = optionBool "ExtraInfoStatistics";
          options.FascistFirewall = optionBool "FascistFirewall";
          options.FetchDirInfoEarly = optionBool "FetchDirInfoEarly";
          options.FetchDirInfoExtraEarly = optionBool "FetchDirInfoExtraEarly";
          options.FetchHidServDescriptors = optionBool "FetchHidServDescriptors";
          options.FetchServerDescriptors = optionBool "FetchServerDescriptors";
          options.FetchUselessDescriptors = optionBool "FetchUselessDescriptors";
          options.ReachableAddresses = optionStrings "ReachableAddresses";
          options.ReachableDirAddresses = optionStrings "ReachableDirAddresses";
          options.ReachableORAddresses = optionStrings "ReachableORAddresses";
          options.GeoIPFile = optionPath "GeoIPFile";
          options.GeoIPv6File = optionPath "GeoIPv6File";
          options.GuardfractionFile = optionPath "GuardfractionFile";
          options.HidServAuth = mkOption {
            description = lib.mdDoc (descriptionGeneric "HidServAuth");
            default = [];
            type = with types; listOf (oneOf [
              (submodule {
                options = {
                  onion = mkOption {
                    type = strMatching "[a-z2-7]{16}\\.onion";
                    description = lib.mdDoc "Onion address.";
                    example = "xxxxxxxxxxxxxxxx.onion";
                  };
                  auth = mkOption {
                    type = strMatching "[A-Za-z0-9+/]{22}";
                    description = lib.mdDoc "Authentication cookie.";
                  };
                };
              })
            ]);
            example = [
              {
                onion = "xxxxxxxxxxxxxxxx.onion";
                auth = "xxxxxxxxxxxxxxxxxxxxxx";
              }
            ];
          };
          options.HiddenServiceNonAnonymousMode = optionBool "HiddenServiceNonAnonymousMode";
          options.HiddenServiceStatistics = optionBool "HiddenServiceStatistics";
          options.HSLayer2Nodes = optionStrings "HSLayer2Nodes";
          options.HSLayer3Nodes = optionStrings "HSLayer3Nodes";
          options.HTTPTunnelPort = optionIsolablePorts "HTTPTunnelPort";
          options.IPv6Exit = optionBool "IPv6Exit";
          options.KeyDirectory = optionPath "KeyDirectory";
          options.KeyDirectoryGroupReadable = optionBool "KeyDirectoryGroupReadable";
          options.LogMessageDomains = optionBool "LogMessageDomains";
          options.LongLivedPorts = optionPorts "LongLivedPorts";
          options.MainloopStats = optionBool "MainloopStats";
          options.MaxAdvertisedBandwidth = optionBandwidth "MaxAdvertisedBandwidth";
          options.MaxCircuitDirtiness = optionInt "MaxCircuitDirtiness";
          options.MaxClientCircuitsPending = optionInt "MaxClientCircuitsPending";
          options.NATDPort = optionIsolablePorts "NATDPort";
          options.NewCircuitPeriod = optionInt "NewCircuitPeriod";
          options.Nickname = optionString "Nickname";
          options.ORPort = optionORPort "ORPort";
          options.OfflineMasterKey = optionBool "OfflineMasterKey";
          options.OptimisticData = optionBool "OptimisticData"; # default is null and like "auto"
          options.PaddingStatistics = optionBool "PaddingStatistics";
          options.PerConnBWBurst = optionBandwidth "PerConnBWBurst";
          options.PerConnBWRate = optionBandwidth "PerConnBWRate";
          options.PidFile = optionPath "PidFile";
          options.ProtocolWarnings = optionBool "ProtocolWarnings";
          options.PublishHidServDescriptors = optionBool "PublishHidServDescriptors";
          options.PublishServerDescriptor = mkOption {
            description = lib.mdDoc (descriptionGeneric "PublishServerDescriptor");
            type = with types; nullOr (enum [false true 0 1 "0" "1" "v3" "bridge"]);
            default = null;
          };
          options.ReducedExitPolicy = optionBool "ReducedExitPolicy";
          options.RefuseUnknownExits = optionBool "RefuseUnknownExits"; # default is null and like "auto"
          options.RejectPlaintextPorts = optionPorts "RejectPlaintextPorts";
          options.RelayBandwidthBurst = optionBandwidth "RelayBandwidthBurst";
          options.RelayBandwidthRate = optionBandwidth "RelayBandwidthRate";
          #options.RunAsDaemon
          options.Sandbox = optionBool "Sandbox";
          options.ServerDNSAllowBrokenConfig = optionBool "ServerDNSAllowBrokenConfig";
          options.ServerDNSAllowNonRFC953Hostnames = optionBool "ServerDNSAllowNonRFC953Hostnames";
          options.ServerDNSDetectHijacking = optionBool "ServerDNSDetectHijacking";
          options.ServerDNSRandomizeCase = optionBool "ServerDNSRandomizeCase";
          options.ServerDNSResolvConfFile = optionPath "ServerDNSResolvConfFile";
          options.ServerDNSSearchDomains = optionBool "ServerDNSSearchDomains";
          options.ServerTransportPlugin = mkOption {
            description = lib.mdDoc (descriptionGeneric "ServerTransportPlugin");
            default = null;
            type = with types; nullOr (submodule ({...}: {
              options = {
                transports = mkOption {
                  description = lib.mdDoc "List of pluggable transports.";
                  type = listOf str;
                  example = ["obfs2" "obfs3" "obfs4" "scramblesuit"];
                };
                exec = mkOption {
                  type = types.str;
                  description = lib.mdDoc "Command of pluggable transport.";
                };
              };
            }));
          };
          options.ShutdownWaitLength = mkOption {
            type = types.int;
            default = 30;
            description = lib.mdDoc (descriptionGeneric "ShutdownWaitLength");
          };
          options.SocksPolicy = optionStrings "SocksPolicy" // {
            example = ["accept *:*"];
          };
          options.SOCKSPort = mkOption {
            description = lib.mdDoc (descriptionGeneric "SOCKSPort");
            default = lib.optionals cfg.settings.HiddenServiceNonAnonymousMode [{port = 0;}];
            defaultText = literalExpression ''
              if config.${opt.settings}.HiddenServiceNonAnonymousMode == true
              then [ { port = 0; } ]
              else [ ]
            '';
            example = [{port = 9090;}];
            type = types.listOf (optionSOCKSPort true);
          };
          options.TestingTorNetwork = optionBool "TestingTorNetwork";
          options.TransPort = optionIsolablePorts "TransPort";
          options.TransProxyType = mkOption {
            description = lib.mdDoc (descriptionGeneric "TransProxyType");
            type = with types; nullOr (enum ["default" "TPROXY" "ipfw" "pf-divert"]);
            default = null;
          };
          #options.TruncateLogFile
          options.UnixSocksGroupWritable = optionBool "UnixSocksGroupWritable";
          options.UseDefaultFallbackDirs = optionBool "UseDefaultFallbackDirs";
          options.UseMicrodescriptors = optionBool "UseMicrodescriptors";
          options.V3AuthUseLegacyKey = optionBool "V3AuthUseLegacyKey";
          options.V3AuthoritativeDirectory = optionBool "V3AuthoritativeDirectory";
          options.VersioningAuthoritativeDirectory = optionBool "VersioningAuthoritativeDirectory";
          #options.VirtualAddrNetworkIPv4 = optionString "VirtualAddrNetworkIPv4";
          # https://gitlab.torproject.org/tpo/core/torsocks/-/issues/14265
          # By default, VirtualAddrNetworkIPv4 is 127.192.0.0/10 and VirtualAddrNetworkIPv6 is [FE80::]/10
          options.VirtualAddrNetworkIPv4 = mkOption {
            type = with types; nullOr str;
            default = "10.192.0.0/10";
            description = lib.mdDoc (descriptionGeneric "VirtualAddrNetworkIPv4");
          };
          #options.VirtualAddrNetworkIPv6 = optionString "VirtualAddrNetworkIPv6";
          options.VirtualAddrNetworkIPv6 = mkOption {
            type = with types; nullOr str;
            default = "[FE80::]/10";
            description = lib.mdDoc (descriptionGeneric "VirtualAddrNetworkIPv6");
          };
          options.WarnPlaintextPorts = optionPorts "WarnPlaintextPorts";
        };
      };
    };
  };

  config = mkIf cfg.enable (
  # FIXME infinite recursion via config
  /*
  assert assertMsg (config.networking.enableIPv6 == false) "IPv6 is not-yet supported. expected: config.networking.enableIPv6 = false;";
  assert assertMsg (config.networking.firewall.enable == true) "expected: config.networking.firewall.enable = true;";
  assert assertMsg (config.networking.nftables.enable == false) "expected: config.networking.nftables.enable = false;";
  assert assertMsg false "wtf";
  assert assertMsg true "wtf 2";
  */
  {
    # Not sure if `cfg.relay.role == "private-bridge"` helps as tor
    # sends a lot of stats
    warnings = optional (
      (
        cfg.settings.BridgeRelay ||
        cfg.relay.enable
      ) &&
      flatten (mapAttrsToList (n: o: o.map) cfg.relay.onionServices) != [])
      ''
        Running Tor hidden services on a public relay makes the
        presence of hidden services visible through simple statistical
        analysis of publicly available data.
        See https://trac.torproject.org/projects/tor/ticket/8742

        You can safely ignore this warning if you don't intend to
        actually hide your hidden services. In either case, you can
        always create a container/VM with a separate Tor daemon instance.
      '' ++
      flatten (mapAttrsToList (n: o:
        optionals (o.settings.HiddenServiceVersion == 2) [
          (optional (o.settings.HiddenServiceExportCircuitID != null) ''
            HiddenServiceExportCircuitID is used in the HiddenService: ${n}
            but this option is only for v3 hidden services.
          '')
        ] ++
        optionals (o.settings.HiddenServiceVersion != 2) [
          (optional (o.settings.HiddenServiceAuthorizeClient != null) ''
            HiddenServiceAuthorizeClient is used in the HiddenService: ${n}
            but this option is only for v2 hidden services.
          '')
          (optional (o.settings.RendPostPeriod != null) ''
            RendPostPeriod is used in the HiddenService: ${n}
            but this option is only for v2 hidden services.
          '')
        ]
      ) cfg.relay.onionServices);

    users.groups.tor.gid = config.ids.gids.tor;
    users.users.tor =
      { description = "Tor Daemon User";
        createHome  = true;
        home        = stateDir;
        group       = "tor";
        uid         = config.ids.uids.tor;
      };

    services.tor.settings = mkMerge [
      (mkIf cfg.enableGeoIP {
        GeoIPFile = "${cfg.package.geoip}/share/tor/geoip";
        GeoIPv6File = "${cfg.package.geoip}/share/tor/geoip6";
      })
      (mkIf cfg.controlSocket.enable {
        ControlPort = [ { unix = runDir + "/control"; GroupWritable=true; RelaxDirModeCheck=true; } ];
      })
      (mkIf cfg.relay.enable (
        optionalAttrs (cfg.relay.role != "exit") {
          ExitPolicy = mkForce ["reject *:*"];
        } //
        optionalAttrs (elem cfg.relay.role ["bridge" "private-bridge"]) {
          BridgeRelay = true;
          ExtORPort.port = mkDefault "auto";
          ServerTransportPlugin.transports = mkDefault ["obfs4"];
          ServerTransportPlugin.exec = mkDefault "${lib.getExe pkgs.obfs4} managed";
        } // optionalAttrs (cfg.relay.role == "private-bridge") {
          ExtraInfoStatistics = false;
          PublishServerDescriptor = false;
        }
      ))
      (mkIf (!cfg.relay.enable) {
        # Avoid surprises when leaving ORPort/DirPort configurations in cfg.settings,
        # because it would still enable Tor as a relay,
        # which can trigger all sort of problems when not carefully done,
        # like the blocklisting of the machine's IP addresses
        # by some hosting providers...
        DirPort = mkForce [];
        ORPort = mkForce [];
        PublishServerDescriptor = mkForce false;
      })
      (mkIf (!cfg.client.enable) {
        # Make sure application connections via SOCKS are disabled
        # when services.tor.client.enable is false
        SOCKSPort = mkForce [ 0 ];
      })
      (mkIf cfg.client.enable (
        { SOCKSPort = [ cfg.client.socksListenAddress ];
        } // optionalAttrs cfg.client.transparentProxy.enable {
          TransPort = [{ addr = "127.0.0.1"; port = 9040; }];
        } // optionalAttrs cfg.client.dns.enable {
          DNSPort = [{ addr = "127.0.0.1"; port = 9053; }];
          AutomapHostsOnResolve = true;
        } // optionalAttrs (flatten (mapAttrsToList (n: o: o.clientAuthorizations) cfg.client.onionServices) != []) {
          ClientOnionAuthDir = runDir + "/ClientOnionAuthDir";
        }
      ))
    ];

    # merged. see below
    /*
    networking.firewall = mkIf cfg.openFirewall {
      allowedTCPPorts =
        concatMap (o:
          if isInt o && o > 0 then [o]
          else optionals (o ? "port" && isInt o.port && o.port > 0) [o.port]
        ) (flatten [
          cfg.settings.ORPort
          cfg.settings.DirPort
        ]);
    };
    */

    # TODO remove
    /*
    # TODO add support for nftables
    # similar: nixpkgs/nixos/modules/services/networking/redsocks.nix
    # similar: nixpkgs/nixos/modules/services/networking/sslh.nix
    # TODO cfg transparent ...
    networking.firewall.extraCommands = mkIf cfg.client.transparentProxy.routeAllTraffic ''
      # https://gitlab.torproject.org/legacy/trac/-/wikis/doc/TransparentProxy

      ### Set variables
      # The UID that Tor runs as (varies from system to system)
      _tor_uid=$(id -u tor)

      # Tor's TransPort
      _trans_port=${cfg.settings.TransPort}

      # Tor's DNSPort
      _dns_port=${cfg.settings.DNSPort}

      # Tor's VirtualAddrNetworkIPv4
      #_virt_addr="10.192.0.0/10"
      _virt_addr=${cfg.settings.VirtualAddrNetworkIPv4}
      # TODO IPv6

      # Your outgoing interface
      #_out_if="eth0"
      _out_if=${cfg.client.transparentProxy.externalInterface}

      # LAN destinations that shouldn't be routed through Tor.
      _non_tor=${builtins.concatStringsSep " " cfg.client.transparentProxy.allowSubnets}

      # IANA reserved blocks.
      _resv_iana=${builtins.concatStringsSep " " cfg.client.transparentProxy.blockSubnets}

      ### Don't lock yourself out after the flush
      #iptables -P INPUT ACCEPT
      #iptables -P OUTPUT ACCEPT

      ### Flush iptables
      iptables -F
      iptables -t nat -F

      ### *nat OUTPUT (For local redirection)
      # nat .onion addresses
      iptables -t nat -A OUTPUT -d $_virt_addr -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $_trans_port

      # nat dns requests to Tor
      iptables -t nat -A OUTPUT -d 127.0.0.1/32 -p udp -m udp --dport 53 -j REDIRECT --to-ports $_dns_port

      # Don't nat the Tor process, the loopback, or the local network
      iptables -t nat -A OUTPUT -m owner --uid-owner $_tor_uid -j RETURN
      iptables -t nat -A OUTPUT -o lo -j RETURN

      # Allow lan access for hosts in $_non_tor
      for _lan in $_non_tor; do
        iptables -t nat -A OUTPUT -d $_lan -j RETURN
      done

      for _iana in $_resv_iana; do
        iptables -t nat -A OUTPUT -d $_iana -j RETURN
      done

      # Redirect all other pre-routing and output to Tor's TransPort
      iptables -t nat -A OUTPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $_trans_port

      ### *filter INPUT
      # Don't forget to grant yourself ssh access from remote machines before the DROP.
      #iptables -A INPUT -i $_out_if -p tcp --dport 22 -m state --state NEW -j ACCEPT

      iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT
      iptables -A INPUT -i lo -j ACCEPT

      # Allow INPUT from lan hosts in $_non_tor
      # Uncomment these 3 lines to enable.
      #for _lan in $_non_tor; do
      # iptables -A INPUT -s $_lan -j ACCEPT
      #done

      # Log & Drop everything else. Uncomment to enable logging
      #iptables -A INPUT -j LOG --log-prefix "Dropped INPUT packet: " --log-level 7 --log-uid
      iptables -A INPUT -j DROP

      ### *filter FORWARD
      iptables -A FORWARD -j DROP

      ### *filter OUTPUT
      iptables -A OUTPUT -m state --state INVALID -j DROP
      iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT

      # Allow Tor process output
      iptables -A OUTPUT -o $_out_if -m owner --uid-owner $_tor_uid -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j ACCEPT

      # Allow loopback output
      iptables -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT

      # Tor transproxy magic
      iptables -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport $_trans_port --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT

      # Allow OUTPUT to lan hosts in $_non_tor
      # Uncomment these 3 lines to enable.
      #for _lan in $_non_tor; do
      # iptables -A OUTPUT -d $_lan -j ACCEPT
      #done

      # Log & Drop everything else. Uncomment to enable logging
      #iptables -A OUTPUT -j LOG --log-prefix "Dropped OUTPUT packet: " --log-level 7 --log-uid
      iptables -A OUTPUT -j DROP

      ### Set default policies to DROP
      iptables -P INPUT DROP
      iptables -P FORWARD DROP
      iptables -P OUTPUT DROP

      ### Set default policies to DROP for IPv6
      #ip6tables -P INPUT DROP
      #ip6tables -P FORWARD DROP
      #ip6tables -P OUTPUT DROP
    '';
    */

    /*
    assert assertMsg (config.networking.enableIPv6 == false) "IPv6 is not-yet supported. expected: config.networking.enableIPv6 = false;";
    assert assertMsg config.networking.firewall.enable "expected: config.networking.firewall.enable = true;";
    assert assertMsg (config.networking.nftables.enable == false) "expected: config.networking.nftables.enable = false;";
    */

    networking.enableIPv6 = false; # TODO force

    # no. just use iptables
    # nixos firewall: deprecate iptables in favor of nftables
    # https://github.com/milahu/nixpkgs/issues/32
    /*
     error: The option `containers.milahuuuc365.networking.nftables.enable' has conflicting definition values:
     - In `/nix/store/914j1h8haf0j7l21ycg419r0603pcp3s-source/modules/services/security/tor.nix': false
     - In `/nix/store/qj4mpzbis3syryphw71ywc8av4hhzp6y-source/nixos/modules/virtualisation/nixos-containers.nix': true
    */
    #networking.nftables.enable = false;

    networking.nameservers = mkIf cfg.client.transparentProxy.routeAllTraffic [
      "127.0.0.1"
    ];

    # based on networking/sslh.nix
    networking.firewall = (mkIf cfg.openFirewall {
      #networking.firewall.enable = true;
      enable = true; # TODO force
      allowedTCPPorts =
        concatMap (o:
          if isInt o && o > 0 then [o]
          else optionals (o ? "port" && isInt o.port && o.port > 0) [o.port]
        ) (flatten [
          cfg.settings.ORPort
          cfg.settings.DirPort
        ]);
    })
    //
    (mkIf cfg.client.transparentProxy.routeAllTraffic (
    # FIXME this shows with services.tor.enable = false
    assert assertMsg (cfg.client.transparentProxy.enable == true) "with services.tor.client.transparentProxy.routeAllTraffic == true: expected: services.tor.client.transparentProxy.enable = true;";
    assert assertMsg (cfg.client.transparentProxy.externalInterface != null) "with services.tor.client.transparentProxy.routeAllTraffic == true: expected: services.tor.client.transparentProxy.externalInterface = \"...\";";
    assert assertMsg (cfg.client.dns.enable == true) "with services.tor.client.transparentProxy.routeAllTraffic == true: expected: services.tor.client.dns.enable = true;";
    assert builtins.length cfg.settings.DNSPort == 1;
    assert builtins.length cfg.settings.TransPort == 1;
    # error: cannot coerce a list to a string
    # ... can be caused by putting the wrong parts of cfg.settings into strings
    #lib.traceSeqN 5 { cfg_settings = cfg.settings; } throw "todo" # debug
    (let
      iptablesCommands = [
        /*
        # networking/sslh.nix
        # DROP martian packets as they would have been if route_localnet was zero
        # Note: packets not leaving the server aren't affected by this, thus sslh will still work
        { table = "raw";    command = "PREROUTING  ! -i lo -d 127.0.0.0/8 -j DROP"; }
        { table = "mangle"; command = "POSTROUTING ! -o lo -s 127.0.0.0/8 -j DROP"; }
        # Mark all connections made by ssl for special treatment (here sslh is run as user ${user})
        { table = "nat";    command = "OUTPUT -m owner --uid-owner ${user} -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j CONNMARK --set-xmark 0x02/0x0f"; }
        # Outgoing packets that should go to sslh instead have to be rerouted, so mark them accordingly (copying over the connection mark)
        { table = "mangle"; command = "OUTPUT ! -o lo -p tcp -m connmark --mark 0x02/0x0f -j CONNMARK --restore-mark --mask 0x0f"; }
        */

        # https://gitlab.torproject.org/legacy/trac/-/wikis/doc/TransparentProxy
        # https://andreafortuna.org/2019/06/19/tor-transparent-proxy-on-linux-a-simple-implementation/

        ### *nat OUTPUT (For local redirection)
        # nat .onion addresses

        { table = "nat"; command = "OUTPUT -d ${cfg.settings.VirtualAddrNetworkIPv4} -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports ${builtins.toString (builtins.elemAt cfg.settings.TransPort 0).port}"; }

        # no. this is not working. dns requests still go to the LAN gateway
        # and onion domains are not resolved
        # blame: -d 127.0.0.1/32
        # nat dns requests to Tor
        # https://gitlab.torproject.org/legacy/trac/-/wikis/doc/TransparentProxy
        # iptables -t nat -A OUTPUT -d 127.0.0.1/32 -p udp -m udp --dport 53 -j REDIRECT --to-ports $_dns_port
        #{ table = "nat"; command = "OUTPUT -d 127.0.0.1/32 -p udp -m udp --dport 53 -j REDIRECT --to-ports ${builtins.toString (builtins.elemAt cfg.settings.DNSPort 0).port}"; }

# TODO will this resolve ALL domains over tor? or only onion domains?
# Since a transparent proxy operates without application support, we have to accept ordinary DNS requests and somehow resolve them through Tor in order to avoid anonymity compromising DNS leaks. Tor versions starting with 0.2.0.1-alpha have a built-in DNSPort designed to operate as a limited DNS server.
# https://gitlab.torproject.org/legacy/trac/-/wikis/doc/TransparentProxy#bsd-pf
# ALL your DNS request will be made through Tor -- anonymous and non-anonymous. This can slow down accessing webpages that you are not accessing anonymously.
# TODO resolv.conf: nameserver 127.0.0.1
# TODO DNSPort 53

        # nat dns requests to Tor
        # https://andreafortuna.org/2019/06/19/tor-transparent-proxy-on-linux-a-simple-implementation/
        # iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353
        { table = "nat"; command = "OUTPUT -p udp --dport 53 -j REDIRECT --to-ports ${builtins.toString (builtins.elemAt cfg.settings.DNSPort 0).port}"; }

        # FIXME wrong? we need nat for internet access
        # Don't nat the Tor process, the loopback, or the local network
        # https://gitlab.torproject.org/legacy/trac/-/wikis/doc/TransparentProxy
        # iptables -t nat -A OUTPUT -m owner --uid-owner $_tor_uid -j RETURN
        { table = "nat"; command = "OUTPUT -m owner --uid-owner ${builtins.toString config.ids.uids.tor} -j RETURN"; }
        # https://andreafortuna.org/2019/06/19/tor-transparent-proxy-on-linux-a-simple-implementation/
        # iptables -t nat -A OUTPUT -m owner --uid-owner 0 -j RETURN

        # Don't nat the Tor process, the loopback, or the local network
        # https://gitlab.torproject.org/legacy/trac/-/wikis/doc/TransparentProxy
        # iptables -t nat -A OUTPUT -o lo -j RETURN
        { table = "nat"; command = "OUTPUT -o lo -j RETURN"; }
      ]

      # TODO same rules for "allow" and "block"?
      # TODO expose this option? only allow access to the LAN gateway
      # Allow lan access for hosts in $_non_tor
      # for _lan in $_non_tor; do
      #   iptables -t nat -A OUTPUT -d $_lan -j RETURN
      # done
      ++ (builtins.map (_lan: { table = "nat"; command = "OUTPUT -d ${_lan} -j RETURN"; }) cfg.client.transparentProxy.allowSubnets)

      # block access to IANA reserved blocks
      # for _iana in $_resv_iana; do
      #   iptables -t nat -A OUTPUT -d $_iana -j RETURN
      # done
      ++ (builtins.map (_iana: { table = "nat"; command = "OUTPUT -d ${_iana} -j RETURN"; }) cfg.client.transparentProxy.blockSubnets)

      ++ [
        # Redirect all other pre-routing and output to Tor's TransPort
        # iptables -t nat -A OUTPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $_trans_port
        { table = "nat"; command = "OUTPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports ${builtins.toString (builtins.elemAt cfg.settings.TransPort 0).port}"; }

        ### *filter INPUT
        # Don't forget to grant yourself ssh access from remote machines before the DROP.
        # # iptables -A INPUT -i $_out_if -p tcp --dport 22 -m state --state NEW -j ACCEPT
        #{ table = "raw"; command = "INPUT -i ${cfg.client.transparentProxy.externalInterface} -p tcp --dport 22 -m state --state NEW -j ACCEPT"; }

        # iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT
        { table = "raw"; command = "INPUT -m state --state ESTABLISHED -j ACCEPT"; }

        # iptables -A INPUT -i lo -j ACCEPT
        { table = "raw"; command = "INPUT -i lo -j ACCEPT"; }
      ]

      # Allow INPUT from lan hosts in ${builtins.concatStringsSep " " cfg.client.transparentProxy.allowSubnets}
      # Uncomment this line to enable.
      #++ (builtins.map (_lan: { table = "raw"; command = "INPUT -s ${_lan} -j ACCEPT"; }) cfg.client.transparentProxy.allowSubnets)

      ++ [
        # Log everything else
        # Uncomment to enable logging
        # # iptables -A INPUT -j LOG --log-prefix "Dropped INPUT packet: " --log-level 7 --log-uid
        #{ table = "raw"; command = "INPUT -j LOG --log-prefix "Dropped INPUT packet: " --log-level 7 --log-uid"; }

        # Drop everything else
        # iptables -A INPUT -j DROP
        { table = "raw"; command = "INPUT -j DROP"; }

        ### *filter FORWARD
        # Drop everything else
        # iptables -A FORWARD -j DROP
        { table = "raw"; command = "FORWARD -j DROP"; }

        ### *filter OUTPUT
        # Drop everything else
        # iptables -A OUTPUT -m state --state INVALID -j DROP
        { table = "raw"; command = "OUTPUT -m state --state INVALID -j DROP"; }

        ### *filter OUTPUT
        # Drop everything else
        # iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT
        { table = "raw"; command = "OUTPUT -m state --state ESTABLISHED -j ACCEPT"; }

        # Allow Tor process output
        # iptables -A OUTPUT -o $_out_if -m owner --uid-owner $_tor_uid -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j ACCEPT
        { table = "raw"; command = "OUTPUT -o ${cfg.client.transparentProxy.externalInterface} -m owner --uid-owner ${builtins.toString config.ids.uids.tor} -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j ACCEPT"; }

        # Allow loopback output
        # iptables -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT
        { table = "raw"; command = "OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT"; }

        # Tor transproxy magic
        # iptables -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport $_trans_port --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT
        { table = "raw"; command = "OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport ${builtins.toString (builtins.elemAt cfg.settings.TransPort 0).port} --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT"; }

      ]

      # Allow OUTPUT to lan hosts in ${builtins.concatStringsSep " " cfg.client.transparentProxy.allowSubnets}
      # # for _lan in $_non_tor; do
      # #  iptables -A OUTPUT -d $_lan -j ACCEPT
      # # done
      # Uncomment this line to enable.
      #++ (builtins.map (_lan: { table = "raw"; command = "OUTPUT -d ${_lan} -j ACCEPT"; }) cfg.client.transparentProxy.allowSubnets)

      ++ [
        # Log everything else. Uncomment to enable logging
        # # iptables -A OUTPUT -j LOG --log-prefix "Dropped OUTPUT packet: " --log-level 7 --log-uid
        #{ table = "raw"; command = "OUTPUT -j LOG --log-prefix "Dropped OUTPUT packet: " --log-level 7 --log-uid"; }

        # Drop everything else. Uncomment to enable logging
        # TODO is this different from iptables -P INPUT DROP
        # iptables -A OUTPUT -j DROP
        { table = "raw"; command = "OUTPUT -j DROP"; }
      ]
      ;

    in
    #lib.traceSeqN 5 { inherit iptablesCommands; } # debug
    {
      # TODO verify /etc/resolv.conf
      # TODO - DNSPort 9053
      # TODO + DNSPort 53
      # no. this would be networking.firewall.nameservers
      # but should be networking.nameservers
      #nameservers = mkForce [ "127.0.0.1" ];

      # TODO disable "sudo" and "wheel" inside the container

      extraCommands = ''
        # Cleanup old iptables entries which might be still there
        # while loop to delete multiple copies of a rule
        ${concatMapStringsSep "\n" ({table, command}: "while iptables -w -t ${table} -D ${command} 2>/dev/null; do :; done") iptablesCommands}

        ${concatMapStringsSep "\n" ({table, command}: "iptables -w -t ${table} -A ${command}"                           ) iptablesCommands}

        ${"" /*
        # networking/sslh.nix
        # Configure routing for those marked packets
        ip rule  add fwmark 0x2 lookup 100
        ip route add local 0.0.0.0/0 dev lo table 100
        */}

        ### Set default policies to DROP
        # TODO is this different from { table = "raw"; command = "OUTPUT -j DROP"; }
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT DROP

      '' + optionalString config.networking.enableIPv6 ''
        ${"" /*
        # Cleanup old iptables entries which might be still there
        # while loop to delete multiple copies of a rule
        ${concatMapStringsSep "\n" ({table, command}: "while ip6tables -w -t ${table} -D ${command} 2>/dev/null; do :; done") ip6tablesCommands}

        ${concatMapStringsSep "\n" ({table, command}: "ip6tables -w -t ${table} -A ${command}"                           ) ip6tablesCommands}
        */}

        ${"" /*
        # networking/sslh.nix
        ip -6 rule  add fwmark 0x2 lookup 100
        ip -6 route add local ::/0 dev lo table 100
        */}

        ### Set default policies to DROP for IPv6
        ip6tables -P INPUT DROP
        ip6tables -P FORWARD DROP
        ip6tables -P OUTPUT DROP
      '';

      extraStopCommands = ''
        ${concatMapStringsSep "\n" ({table, command}: "iptables -w -t ${table} -D ${command}") iptablesCommands}

        ${"" /*
        # networking/sslh.nix
        ip rule  del fwmark 0x2 lookup 100
        ip route del local 0.0.0.0/0 dev lo table 100
        */}

        ### Set default policies to ACCEPT
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
      '' + optionalString config.networking.enableIPv6 ''
        ${concatMapStringsSep "\n" ({table, command}: "ip6tables -w -t ${table} -D ${command}") ip6tablesCommands}

        ${"" /*
        # networking/sslh.nix
        ip -6 rule  del fwmark 0x2 lookup 100
        ip -6 route del local ::/0 dev lo table 100
        */}

        ### Set default policies to ACCEPT for IPv6
        ip6tables -P INPUT ACCEPT
        ip6tables -P FORWARD ACCEPT
        ip6tables -P OUTPUT ACCEPT
      '';
    })));

    systemd.services.tor = {
      description = "Tor Daemon";
      path = [ pkgs.tor ];

      wantedBy = [ "multi-user.target" ];
      after    = [ "network.target" ];
      restartTriggers = [ torrc ];

      serviceConfig = {
        Type = "simple";
        User = "tor";
        Group = "tor";
        ExecStartPre = [
          "${cfg.package}/bin/tor -f ${torrc} --verify-config"
          # DOC: Appendix G of https://spec.torproject.org/rend-spec-v3
          ("+" + pkgs.writeShellScript "ExecStartPre" (concatStringsSep "\n" (flatten (["set -eu"] ++
            mapAttrsToList (name: onion:
              optional (onion.authorizedClients != []) ''
                rm -rf ${escapeShellArg onion.path}/authorized_clients
                install -d -o tor -g tor -m 0700 ${escapeShellArg onion.path} ${escapeShellArg onion.path}/authorized_clients
              '' ++
              imap0 (i: pubKey: ''
                echo ${pubKey} |
                install -o tor -g tor -m 0400 /dev/stdin ${escapeShellArg onion.path}/authorized_clients/${toString i}.auth
              '') onion.authorizedClients ++
              optional (onion.secretKey != null) ''
                install -d -o tor -g tor -m 0700 ${escapeShellArg onion.path}
                key="$(cut -f1 -d: ${escapeShellArg onion.secretKey} | head -1)"
                case "$key" in
                 ("== ed25519v"*"-secret")
                  install -o tor -g tor -m 0400 ${escapeShellArg onion.secretKey} ${escapeShellArg onion.path}/hs_ed25519_secret_key;;
                 (*) echo >&2 "NixOS does not (yet) support secret key type for onion: ${name}"; exit 1;;
                esac
              ''
            ) cfg.relay.onionServices ++
            mapAttrsToList (name: onion: imap0 (i: prvKeyPath:
              let hostname = removeSuffix ".onion" name; in ''
              printf "%s:" ${escapeShellArg hostname} | cat - ${escapeShellArg prvKeyPath} |
              install -o tor -g tor -m 0700 /dev/stdin \
               ${runDir}/ClientOnionAuthDir/${escapeShellArg hostname}.${toString i}.auth_private
            '') onion.clientAuthorizations)
            cfg.client.onionServices
          ))))
        ];
        ExecStart = "${cfg.package}/bin/tor -f ${torrc}";
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        KillSignal = "SIGINT";
        TimeoutSec = cfg.settings.ShutdownWaitLength + 30; # Wait a bit longer than ShutdownWaitLength before actually timing out
        Restart = "on-failure";
        LimitNOFILE = 32768;
        RuntimeDirectory = [
          # g+x allows access to the control socket
          "tor"
          "tor/root"
          # g+x can't be removed in ExecStart=, but will be removed by Tor
          "tor/ClientOnionAuthDir"
        ];
        RuntimeDirectoryMode = "0710";
        StateDirectoryMode = "0700";
        StateDirectory = [
            "tor"
            "tor/onion"
          ] ++
          flatten (mapAttrsToList (name: onion:
            optional (onion.secretKey == null) "tor/onion/${name}"
          ) cfg.relay.onionServices);
        # The following options are only to optimize:
        # systemd-analyze security tor
        RootDirectory = runDir + "/root";
        RootDirectoryStartOnly = true;
        #InaccessiblePaths = [ "-+${runDir}/root" ];
        UMask = "0066";
        BindPaths = [ stateDir ];
        BindReadOnlyPaths = [ storeDir "/etc" ] ++
          optionals config.services.resolved.enable [
            "/run/systemd/resolve/stub-resolv.conf"
            "/run/systemd/resolve/resolv.conf"
          ];
        AmbientCapabilities   = [""] ++ lib.optional bindsPrivilegedPort "CAP_NET_BIND_SERVICE";
        CapabilityBoundingSet = [""] ++ lib.optional bindsPrivilegedPort "CAP_NET_BIND_SERVICE";
        # ProtectClock= adds DeviceAllow=char-rtc r
        DeviceAllow = "";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateMounts = true;
        PrivateNetwork = mkDefault false;
        PrivateTmp = true;
        # Tor cannot currently bind privileged port when PrivateUsers=true,
        # see https://gitlab.torproject.org/legacy/trac/-/issues/20930
        PrivateUsers = !bindsPrivilegedPort;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        RemoveIPC = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        # See also the finer but experimental option settings.Sandbox
        SystemCallFilter = [
          "@system-service"
          # Groups in @system-service which do not contain a syscall listed by:
          # perf stat -x, 2>perf.log -e 'syscalls:sys_enter_*' tor
          # in tests, and seem likely not necessary for tor.
          "~@aio" "~@chown" "~@keyring" "~@memlock" "~@resources" "~@setuid" "~@timer"
        ];
        SystemCallArchitectures = "native";
        SystemCallErrorNumber = "EPERM";
      };
    };

    environment.systemPackages = [ cfg.package ];
  });

  meta.maintainers = with lib.maintainers; [ julm ];
}
