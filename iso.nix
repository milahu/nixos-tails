/*
TODO
zeronet
securedrop? secudrop? secushare?
bitmessage

tails/config/chroot_local-packageslists/tails-common.list

tails/config/chroot_local-includes/

tails/config/chroot_local-patches/

tails/config/chroot_local-hooks/
*/

/*
nix-build '<nixpkgs/nixos>' -A config.system.build.isoImage -I nixos-config=iso.nix
qemu-system-x86_64 -enable-kvm -m 256 -cdrom result/iso/nixos-*.iso

TODO
argos-translate and/or libretranslate -> offline translator
...
all packages from tailsnano notes 
use deb2nix to translate package names
https://github.com/milahu/deb2nix

browser bookmarks: dark.fail tordir ...

gpg keys of all vendors

*/

{ lib
, pkgs
, config
, ...
}:

let

  patchedPackages = rec {
    curl = (pkgs.curl.overrideAttrs (oldAttrs: {
      patches = (oldAttrs.patches or []) ++ [
        # add support for CURL_ALLOW_DOT_ONION=1
        # fix: I want to resolve onion addresses
        # https://github.com/curl/curl/discussions/11125
        # https://github.com/curl/curl/pull/11236
        (pkgs.fetchurl {
          url = "https://github.com/curl/curl/pull/11236.patch";
          sha256 = "sha256-7UMLiUJEZglACu5oF4A5CTKbFyJptmpulYGJmIgP/Wc=";
        })
      ];
    }));
    git = (pkgs.git.override {
      inherit curl;
    });
  };

in

{

  # override nixos modules
  # https://stackoverflow.com/a/46407944/10440128
  disabledModules = [
    # override nixos module services/security/tor.nix
    "services/security/tor.nix"
  ];

  imports = [
    # ?
    <nixpkgs/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix>
    #<nixpkgs/nixos/modules/installer/cd-dvd/installation-cd-base.nix>

    # Provide an initial copy of the NixOS channel so that the user
    # doesn't need to run "nix-channel --update" first.
    <nixpkgs/nixos/modules/installer/cd-dvd/channel.nix>

    # override nixos module services/security/tor.nix
    ./modules/services/security/tor.nix

    # TODO? move nixos config to configuration.nix
    #./configuration.nix

    # nixos-generate-config
    #./hardware-configuration.nix
  ];



  nixpkgs = {
    hostPlatform = lib.mkDefault "x86_64-linux";
    config.allowUnfree = true;
  };

  #nixpkgs.overlays

  nixpkgs.config.packageOverrides = pkgs: {
    nur = import (
      #builtins.fetchTarball "https://github.com/nix-community/NUR/archive/master.tar.gz"
      builtins.fetchTarball {
        url = (
          let
            rev = "758483969436e4a5f202760e7f158704572df459";
          in
          "https://github.com/nix-community/NUR/archive/${rev}.tar.gz"
        );
        sha256 = "sha256:04nh523w42gi8hh7vadz4jcl0qmhc60z2zgx2k7pjs96vaxfza48";
      }
    ) {
      inherit pkgs;
    };

  };

  nix = {
    # enable flakes by default
    #settings.experimental-features = ["nix-command" "flakes"];
    extraOptions = "experimental-features = nix-command flakes";
  };



  boot = {
    kernelPackages = pkgs.linuxPackages_latest;
    supportedFilesystems = lib.mkForce [
      "btrfs"
      "reiserfs"
      "vfat"
      "f2fs"
      "xfs"
      "ntfs"
      "cifs"
    ];
  };



  networking = {
    hostName = "amnesia";
  };

/*
  networking = {
    #hostId = "deadbeef";
    #hostName = "example";
    networkmanager.enable = true;
    useDHCP = false;
  };
*/




  # https://nixos.wiki/wiki/Tor
  services.tor = {
    # slow (but secure) socks proxy on port 9050: one circuit per destination address
    enable = true;

    client = {

      # fast (but risky) socks proxy on port 9063 for https: new circuit every 10 minutes
      enable = true;

      # this will add:
      # settings.TransPort = [{ addr = "127.0.0.1"; port = 9040; }]
      transparentProxy.enable = true;

      # TODO restore
      # TODO test
      /*
      curl -s https://check.torproject.org/api/ip
      */
      transparentProxy.routeAllTraffic = true;

      # patchedpackages.curl is wrong?
      # no. blame .curlrc

      #transparentProxy.externalInterface = "ve-milahuuuc365"; # TODO? via "ve-*"
      transparentProxy.externalInterface = "eth0"; # or eth0@if4
      #transparentProxy.externalInterface = "eth0@if4";
      # this will add:
      # settings.DNSPort = [{ addr = "127.0.0.1"; port = 9053; }];
      # settings.AutomapHostsOnResolve = true;
      dns.enable = true;

    };
    # disable by-country statistics
    enableGeoIP = false;
    #openFirewall = true;
    settings = {
      #ORPort = 9000;
    };
  };

  # https://gitea.com/curben/blog/src/branch/master/source/_posts/tor-hidden-onion-nixos.md
  services.tor.relay.onionServices = {
    # gitea server
    # keys are stored in /var/lib/tor/onion
    "TODO" = {
      map = [
        { port = 80; target = { port = 80; }; } # lighttpd
      ];

      # FIXME implement this
      # no. run tor + gitea in a container
      #useSeparateTorProcess = true;

      # ... or default
      # useSeparateTorProcess = null;
      # and disable the warning with
      #useSeparateTorProcess = false;

      #version = 3;
      settings = {
        #TODO default in tor-insecure
        # FIXME this requires tor.client = false
        # https://github.com/NixOS/nixpkgs/pull/48625
        #HiddenServiceSingleHopMode = true; # NON ANONYMOUS. use tor only for NAT punching
        #HiddenServiceNonAnonymousMode = true; # TODO verify. use extraConfig?
        #SocksPort = 0;
        #HiddenServicePort = 80; # ?
      };
    };
  };



  /*
  # fix: gnome power settings do not turn off screen
  # https://haseebmajid.dev/posts/2024-02-04-how-to-create-a-custom-nixos-iso/
  systemd = {
    services.sshd.wantedBy = pkgs.lib.mkForce ["multi-user.target"];
    targets = {
      sleep.enable = false;
      suspend.enable = false;
      hibernate.enable = false;
      hybrid-sleep.enable = false;
    };
  };
  */



  # limit size of /var/log/journal
  # journalctl --vacuum-size=20M
  services.journald.extraConfig = ''
    SystemMaxUse=20M
  '';



  # Set your time zone.
  time.timeZone = "Europe/Berlin";

  # locale
  i18n.defaultLocale = "en_US.UTF-8";
  i18n.extraLocaleSettings = {
    LC_MESSAGES = "en_US.UTF-8";
    LC_TIME = "de_DE.UTF-8";
    LC_CTYPE = "en_US.UTF-8";
    # TODO print layout + time format
  };

  # The global useDHCP flag is deprecated, therefore explicitly set to false here.
  # Per-interface useDHCP will be mandatory in the future, so this generated config
  # replicates the default behaviour.
  networking.useDHCP = false;

  #networking.interfaces.enp0s25.useDHCP = true;
  #networking.interfaces.enp0s25.useDHCP = false;
  #networking.interfaces.wls1.useDHCP = true; # wifi

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  # FIXME networkmanager breaks br0 for container networking
  networking.networkmanager.enable = true;
  # https://nlewo.github.io/nixos-manual-sphinx/configuration/network-manager.xml.html
  # https://developer-old.gnome.org/NetworkManager/stable/NetworkManager.conf.html#device-spec
  # networking.networkmanager.unmanaged  = [ "*" "except:type:wwan" "except:type:gsm" ]; # TODO why "*" ?!
  networking.networkmanager.unmanaged  = [
    # TODO move this to containers, avoid globbing
    "interface-name:br*" # br0
    "interface-name:ve-*" # ve-milahuuuc365
    "interface-name:vb-*" # vb-milahuuuc365
    # TODO move this to docker, avoid globbing
    "interface-name:docker*" # docker0
  ];

  # bypass networking.networkmanager
  #networking.defaultGateway = "192.168.178.1";

  # Select internationalisation properties.
  # i18n.defaultLocale = "en_US.UTF-8";

  console.keyMap = "de";
  console.font = "ter-i32b"; # large font
  #console.font = "Lat2-Terminus16";
  #console.packages = options.console.packages.default ++ [ pkgs.terminus_font ];
  #console.packages = console.packages.default ++ [ pkgs.terminus_font ];
  console.packages = [ pkgs.terminus_font ];
  console.earlySetup = true; # set font early in boot

  services.xserver.enable = true;
  # Configure keymap in X11
  services.xserver.xkb.layout = "de";
  services.xserver.xkb.options  = "eurosign:e";
  services.xserver.videoDrivers = [ "intel" ];
  #services.xserver.useGlamor = true; # TODO?

  #services.xserver.displayManager.autoLogin.enable = true;
  #services.xserver.displayManager.autoLogin.user = "user";



  environment.variables = {
    # fix: curl: Not resolving .onion address (RFC 7686)
    CURL_ALLOW_DOT_ONION = "1";
  };

  # https://nixos.wiki/wiki/Tor
  services.tor = {
    # slow (but secure) socks proxy on port 9050: one circuit per destination address
    enable = true;

    client = {

      # fast (but risky) socks proxy on port 9063 for https: new circuit every 10 minutes
      enable = true;

      # this will add:
      # settings.TransPort = [{ addr = "127.0.0.1"; port = 9040; }]
      transparentProxy.enable = true;

      # TODO restore
      # TODO test
      /*
      curl -s https://check.torproject.org/api/ip
      */
      transparentProxy.routeAllTraffic = true;

      # patchedpackages.curl is wrong?
      # no. blame .curlrc

      #transparentProxy.externalInterface = "ve-milahuuuc365"; # TODO? via "ve-*"
      transparentProxy.externalInterface = "eth0"; # or eth0@if4
      #transparentProxy.externalInterface = "eth0@if4";

      # this will add:
      # settings.DNSPort = [{ addr = "127.0.0.1"; port = 9053; }];
      # settings.AutomapHostsOnResolve = true;
      dns.enable = true;

    };
    # disable by-country statistics
    enableGeoIP = false;
    #openFirewall = true;
    settings = {
      #ORPort = 9000;
    };
  };



  # Enable CUPS to print documents.
  services.printing.enable = true;

  # journalctl --catalog --follow --unit=cups
  services.printing.logLevel = "debug";

  # discover network printers
  services.avahi.enable = true;
  services.avahi.nssmdns4 = true;

  # discover wifi printers
  services.avahi.openFirewall = true;

  #services.printing.extraConf = ''LogLevel debug'';
  # systemctl status -l cups.service

  services.printing.drivers =
  let
    # TODO:    nur.repos.milahu.brother-hll3210cw # brother HL-L3210CW
    #brother-hll3210cw = (pkgs.callPackage /home/user/src/nixos/milahu--nixos-packages/nur-packages/pkgs/brother-hll3210cw/default.nix { });
  in
  [ 
    #    pkgs.gutenprint
    #    pkgs.gutenprintBin # canon etc
    #pkgs.hplip pkgs.hplipWithPlugin # hp
    #pkgs.samsungUnifiedLinuxDriver pkgs.splix # samsung

    pkgs.brlaser # brother # not?
    #    brother-hll3210cw
    pkgs.brgenml1lpr # brother # TODO

    # hll6400dwlpr-3.5.1-1
    /*
    (pkgs.callPackage /home/user/src/nixpkgs/brother-hl-l6400dw/nixpkgs/pkgs/misc/cups/drivers/brother/hll6400dw/default.nix {}).driver
    (pkgs.callPackage /home/user/src/nixpkgs/brother-hl-l6400dw/nixpkgs/pkgs/misc/cups/drivers/brother/hll6400dw/default.nix {}).cupswrapper
    */
    #(pkgs.callPackage /home/user/src/nixpkgs/brother-hl-l6400dw/nixpkgs/pkgs/misc/cups/drivers/brother/hll6400dw/default.nix {})
    #pkgs.nur.repos.milahu.brother-hll6400dw
    pkgs.nur.repos.milahu.brother-hll5100dn
    #pkgs.nur.repos.milahu-local.brother-hll5100dn

    # samsung
    pkgs.gutenprint
    pkgs.gutenprintBin
  ];



  # scanners
  hardware.sane = {
    enable = true;
    brscan4.enable = true;
    brscan5.enable = true;
  };



  # === KDE SDDM ===
  # kde login
  #services.xserver.displayManager.sddm.enable = true;
  services.displayManager.sddm.enable = true;

  # kde desktop
  # breaks GTK apps: inkscape evolution
  services.xserver.desktopManager.plasma5.enable = true;
  # broken since setting dpi to 144 ... login hangs with black screen
  # broken. desktop hangs again and again ...
  # -> $HOME/bin/plasmashell-restart.sh



  # xfce desktop
  # FIXME keeps crashing over night
  # in the morning, i have a black screen
  # and must restart the display-manager.service
  # -> kde plasma
  #services.xserver.desktopManager.xfce.enable = true;



  # no
  # tails linux has gnome desktop by default
  # but i hate gnome...
  # gnome is too "simple"...
  # gnome is too much "like macos but less perfect"
  /*
  # gnome login
  # broken: display-manager.service hangs at "starting X11 server..."
  services.xserver.displayManager.gdm.enable = true;

  # gnome desktop
  # gnome is still gay.
  # gnome is still SHIT. gnome-shell still has a memory leak -> needs 2.6 GByte RAM after some days of uptime
  # cannot scale display to 150% (only 100% or 200%)
  # terminal is gay (cannot rename tabs)
  # -> back to kde
  services.xserver.desktopManager.gnome.enable = true;

  environment.gnome.excludePackages = (with pkgs; [
    gnome-photos
    gnome-tour
    ]) ++ (with pkgs.gnome; [
    cheese # screenshot tool
    gnome-music
    #gnome-terminal
    #gedit
    epiphany
    #evince
    #gnome-characters
    totem # video player
    geary
    # games?
    tali
    iagno
    hitori
    atomix
  ]);

  # gnome
  # fix:  dconf-WARNING **: failed to commit changes to dconf: GDBus.Error:org.freedesktop.DBus.Error.ServiceUnknown: The name ca.desrt.dconf was not provi>
  programs.dconf.enable = true;

  # gnome
  services.udev.packages = with pkgs; [
    gnome3.gnome-settings-daemon
  ];
  */



  environment.systemPackages =
  (with patchedPackages; [
    curl
    git
    #gitea
    #cgit-pink
  ])
  ++
  (with pkgs; [

    git
    git-filter-repo

    # chat
    element-desktop # matrix. heavy...
    session-desktop
    tdesktop # telegram
    pidgin
    pidgin-otr # off the record
    #(pidgin.withPlugins (p: with p; [ ... ])) # ?
    hexchat # irc
    #bitmessage # TODO
    #zeronet # FIXME insecure

    linuxPackages.cpupower

    nix-index # nix-locate
    cached-nix-shell # Instant startup time for nix-shell

    gimp
    inkscape

    #virt-manager
    iptables # debug: iptables -L -v -t nat
    #git
    #curl
    wget # TODO resolve onion
    jq
    yaml2json
    dig # dns client. dig +trace example.com
    netselect # sort servers by latency

    nano
    neovim

    # based on tor
    tor-browser
    onionshare
    nur.repos.milahu.ricochet-refresh
    # TODO more

    mpv

    # TODO music player
    # TODO update nixpkgs
    quodlibet
    strawberry

    hunspell # spell checker
    hunspellDicts.de_DE
    hunspellDicts.en_US-large
    # TODO more langs

    pdftk
    poppler_utils # pdfimages

    libreoffice-fresh
    # TODO more langs?

    okular # document viewer, ebook reader

    ffmpeg_6-full
    sox
    audacity


    mmv # multi move
    pv # pipe viewer (progress, rate)
    tree
    onboard # virtual keyboard
    killall
    unixtools.xxd # encode/decode hex strings to/from bytes

    # TODO moreutils without parallel or rename to parallel.moreutils like in ubuntu/debian
    moreutils # sponge: soak up stdin/write to file

    parallel-full

    unzip
    zip # deflate
    brotli
    zstd
    bzip2
    bzip3
    xz # lzma
    rar
    p7zip # 7z # TODO replace with _7zz? https://github.com/p7zip-project/p7zip/issues/225
    p7zip.doc
    #lzham
    lz4
    #lrzip
    #zpaq
    libarchive # bsdtar, bsdcpio

    pinentry
    pinentry.qt

    html-tidy # fix broken html files

    expect # unbuffer

    sane-backends # scanner, tool: scanimage
    sane-frontends # scanadf

    usbutils # lsusb
    pciutils # lspci

    imagemagick # convert

    # better than imagemagick for jp2 images?
    # img2pdf -o sample.pdf sample.jp2
    python3Packages.img2pdf

    #ark # kde archive manager

    #gwenview # image viewer # FIXME broken
    feh # image viewer # TODO less lightweight?

    xfce.orage # calendar

    spectacle # screenshot

    vscodium
    # TODO nixos configuration "nixd" "vscodium" "home-manager" "settings.json" "nix.serverSettings"

    yt-dlp
    #nur.repos.milahu.yt-dlp

    nodejs_latest

    #python3
    (python3.withPackages (pp: with pp; [
      pyaml
      requests
    ]))

    libdeflate
    zlib

    #    rubyPackages.nokogiri # huginn
    jq # json query
    gron # make json greppable

    qbittorrent # TODO vpn only for this app

    gst_all_1.gst-plugins-good # gstreamer plugins

    #cachix # cachix use nix-community
    # Enable the Nix Community cache:
    # https://github.com/nix-community/redoxpkgs

    htop # monitor cpu + memory
    iotop # monitor disks
    #nethogs # monitor network by process
    #iftop # monitor network by connection
    nmap # network port scanner

    bintools-unwrapped # nm strings ...
    file
    binwalk
    #python3.pkgs.matplotlib # FIXME not found by binwalk
    strace
    ltrace
    gdb
    binwalk
    lsof

    thinkfan # laptop fan control
    lm_sensors # sensors: temperature ...
    smartmontools # smartctl: hard drive health status

    #direnv # use .envrc files

    xclip

    libjpeg # jpegtran, lossless jpeg transforms

    fbida # exiftran, lossless jpeg transforms

    nixpkgs-fmt

    patchelf

    # nix run github:nix-community/nix-init -- --help
    nix-init

    k3b # cd/dvd writer

    # k3b dependencies:
    dvdplusrwtools # growisofs dvd+rw-format
    #cdrtools # cdrecord
    cdrkit # cdrecord

    python3.pkgs.memory_profiler # mprof

    bc # calculator

    bbe # binary sed

    sqlite

    # partition, format, filesystem
    gparted
    btrfs-progs
    xfsprogs
    exfatprogs

    mlocate # mlocate, updatedb # find files in a filesystem with a cached database

    rsync
    rclone

    # fix: man 3 crypt
    # via: man 5 shadow
    man-pages

    openssl
    nss.tools # certutil to add certs to $HOME/.pki

    nano-wallet # nanocoin, nanocurrency
    #nur.repos.milahu.nano-node # FIXME NUR eval error
    monero monero-gui
    # TODO haveno

    datamash # math. sum. average

    gnumake # many builds are based on makefiles: native node modules, ...

    pkg-config # required by some build tools

    dos2unix

    keepassxc # password manager

    torrenttools

    # TODO install browser extension: video downloadhelper
    nur.repos.milahu.vdhcoapp

  ]);

  # compress faster
  isoImage.squashfsCompression = "gzip -Xcompression-level 1";



  # TODO efi?
  # https://github.com/nix-community/nixos-generators/raw/master/formats/raw.nix
  # https://github.com/nix-community/nixos-generators/raw/master/formats/raw-efi.nix

  # After booting, if you intend to use nixos-switch, consider using nixos-generate-config.
  # ?

  fileSystems."/" = {
    device = "/dev/disk/by-label/nixos";
    autoResize = true;
    fsType = "ext4";
  };

  boot = {
    growPartition = true;
    kernelParams = [
      # https://github.com/nix-community/nixos-generators
      # log to serial console, not to display
      "console=ttyS0"
      # log to display
      # "console=tty0"
    ];
    loader.grub.device = lib.mkDefault "/dev/vda";
    loader.timeout = lib.mkDefault 0;
    initrd.availableKernelModules = [
      "uas"
    ];
  };

  # add root user
  # get a recovery shell when boot fails
  users.users."root".password = "root";
  services.openssh.settings.PermitRootLogin = lib.mkForce "yes";

  # allow to change the passwords after boot
  users.mutableUsers = true;



  services.qemuGuest.enable = true;



  # increase size of /run/user/1000 (max = ram + swap = 8 + 16 = 24)
  # swap -> /etc/nixos/hardware-configuration.nix
  # https://unix.stackexchange.com/questions/597024/how-to-resize-the-run-directory
  services.logind.extraConfig = ''
    RuntimeDirectorySize=12G
    HandleLidSwitchDocked=ignore
  '';

  # Enable sound.
  sound.enable = true;
  hardware.pulseaudio.enable = true;

  # Enable touchpad support (enabled default in most desktopManager).
  services.libinput.enable = true;

  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users."amnesia" = {
    isNormalUser = true;
    extraGroups = [
      "wheel" # Enable ‘sudo’ for the user.
      "docker" # WARNING the docker group membership is effectively equivalent to being root! https://github.com/moby/moby/issues/9976
      "dialout" # arduino programming
      "cdrom" # burn cd/dvd
      "libvirtd" # virt-manager, virtualbox
    ];
  };

  # TODO
  #home-manager.users."amnesia" = import ./home.nix;

  # https://nixos.wiki/wiki/Fonts
  fonts.packages = with pkgs; [
    #corefonts # microsoft core fonts: impact, ...

    /*
      open-sans
      noto-fonts
      #noto-fonts-cjk
      #noto-fonts-emoji
      liberation_ttf
    */

    fira-code
    #fira-code-symbols
    #mplus-outline-fonts # error: A definition for option `fonts.fonts.[definition 1-entry 2]' is not of type `path'. Definition values:
    dina-font
    proggyfonts
    #(nerdfonts.override { fonts = [
    #"FiraCode"
    #"DroidSansMono"
    #  "nf-dev-coda"
    #]; })
  ];


  #virtualisation.docker.enable = true;
  virtualisation.podman.enable = true;
  virtualisation.podman.dockerCompat = true;


  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  programs.mtr.enable = true;
  programs.gnupg.agent = {
    enable = true;
    enableSSHSupport = true; # /etc/ssh/ssh_config
    # fix? gpg: agent_genkey failed: No pinentry
    # todo: also add pinentry to env pkgs
    pinentryPackage = pkgs.pinentry-qt; # kde
    #pinentryPackage = pkgs.pinentry-gnome3; # gnome
    #pinentryPackage = pkgs.pinentry-gtk2; # gnome
  };



  # debug
  #networking.firewall.enable = false;

  #networking.enableIPv6 = false;

  networking.firewall.allowedTCPPorts = lib.mkForce [
    7075 # nano-wallet
  ];

  networking.firewall.allowedUDPPorts = lib.mkForce [
  ];

  networking.firewall.allowedTCPPortRanges = lib.mkForce [
    { from = 6881; to = 6889; } # bittorrent
  ];

  networking.firewall.allowedUDPPortRanges = lib.mkForce [
    { from = 6881; to = 6889; } # bittorrent
  ];


  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "20.09"; # Did you read the comment?


  programs.firejail = {
    enable = true;
  };

  # ?
  security.chromiumSuidSandbox.enable = true;





  # darkmode boot splash image
  # https://github.com/NixOS/nixos-artwork/pull/86
  # darkmode
  # colors flipped
  # removed shadow from "sel" text
  # light-blue for "sel" background

  isoImage.efiSplashImage = pkgs.fetchurl {
    url = "https://raw.githubusercontent.com/NixOS/nixos-artwork/96a76e36e6c7442b922b5ff70689d5aa8b7c244a/bootloader/efi-background-dark.png";
    sha256 = "sha256-4JanJiL7fLnArHTklqGL++5TDoZSF1P5GDImKGcT0O4=";
  };

  isoImage.splashImage = pkgs.fetchurl {
    url = "https://raw.githubusercontent.com/NixOS/nixos-artwork/96a76e36e6c7442b922b5ff70689d5aa8b7c244a/bootloader/isolinux/bios-boot-dark.png";
    sha256 = "sha256-W/Qg0O5PXRYGr80qUCdToqhMsI8mAuxiUnliKoZhGgI=";
  };

  isoImage.syslinuxTheme = ''
    MENU TITLE NixOS
    MENU RESOLUTION 800 600
    MENU CLEAR
    MENU ROWS 6
    MENU CMDLINEROW -4
    MENU TIMEOUTROW -3
    MENU TABMSGROW  -2
    MENU HELPMSGROW -1
    MENU HELPMSGENDROW -1
    MENU MARGIN 0
    #                                FG:AARRGGBB  BG:AARRGGBB   shadow
    MENU COLOR BORDER       30;44      #00000000    #00000000   none
    MENU COLOR SCREEN       37;40      #FFFFFFFF    #00000000   none
    MENU COLOR TABMSG       31;40      #80FFFFFF    #00000000   none
    MENU COLOR TIMEOUT      1;37;40    #FFFFFFFF    #00000000   none
    MENU COLOR TIMEOUT_MSG  37;40      #FFFFFFFF    #00000000   none
    MENU COLOR CMDMARK      1;36;40    #FFFFFFFF    #00000000   none
    MENU COLOR CMDLINE      37;40      #FFFFFFFF    #00000000   none
    MENU COLOR TITLE        1;36;44    #00000000    #00000000   none
    MENU COLOR UNSEL        7;37;40    #FFFFFFFF    #00000000   none
    MENU COLOR SEL          37;44      #FF000000    #FF7ebae4   none
  '';

}
