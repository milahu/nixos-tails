# nixos-tails

[tails linux](https://gitlab.tails.boum.org/tails/tails) based on [nixos linux](https://github.com/NixOS/nixpkgs)

[tails linux](https://gitlab.tails.boum.org/tails/tails) implemented in [the nix language](https://github.com/NixOS/nix)



## help wanted

oi mates! lets do this.

i started an early draft of this project,
but i will probably never finish this project due to lack of time.

this is "concept art", a concept waiting to be implemented.

my gift-curse is: i start everything, and finish nothing.

so im looking for people with the opposite gift-curse: i finish everything, and start nothing.



## must be based on the Nix language

[nixos linux](https://github.com/NixOS/nixpkgs) is simply the best linux distro. period.

[the nix language](https://github.com/NixOS/nix) allows to build "perfect" operating systems with "infinite" complexity.



## todo



### handle dynamic parameters of image generation

- localization: language, location
- USB drive size



### encrypted persistent storage

on USB drive



### torify all network access

when a new network connection is detected,
show a popup to ask: how to connect to tor?

let user set tor bridges, etc



### micromanage app settings

- darkmode for everything by default



#### KDE plasma settings

- night color
  - temp: 1000K = extreme warm
  - location: latitude, longitude
    - TODO can we "single source" this config?



#### browser extensions

- dark reader - darkmode
- ublock - adblocker
- video downloadhelper
- hypothesis - annotations
- noscript - javascript blocker
- tampermonkey - userscripts
- stylebot - custom styles
- some captcha solver extension
- keepassxc
  - integration with gpg?
- integration with XMR monero wallet?
- integration with XNO nano wallet?



#### browser bookmarks

- tor.taxi
- dark.fail
- erowid.com
- seedfinder.eu
- wiki.tripsit.me
- psychonautwiki.org



### make this work on 32bit hardware

if this project should be relevant in the future,
it must be compatible with lowtech hardware.

http://collapseos.org/why.html

<blockquote>

32-bit? 16-bit?

Why go as far as 8-bit machines?
There are some 32-bit ARM chips around that are protoboard-friendly.

First, because I think there are more scavenge-friendly 8-bit chips around
than scavenge-friendly 16-bit or 32-bit chips.

Second, because those chips will be easier to replicate in a post-collapse fab.
The z80 has 9000 transistors. 9000!
Compared to the millions we have in any modern CPU, that's nothing!
If the first chips we're able to create post-collapse have a low transistor count,
we might as well design a system that works well on simpler chips.

That being said, nothing stops the project from including
the capability of programming an ARM or RISC-V chip.

</blockquote>



#### Tails Linux requires 64bit

64bit sounds fancy for 10% better security,
but if you simply dont have 64bit hardware, then its 100% useless.

https://www.theregister.com/2017/02/06/tails_privacy_linux_farewelling_32bit_processors_from_30/

<blockquote>

Tails Linux farewells 32-bit processors with imminent version 3.0

Security-centric distro also has some fixes in new version 2.10

by Richard Chirgwin

Mon 6 Feb 2017 // 05:57 UTC

The privacy-paranoid Linux distribution Tails has decided it's time to send 32-bit distributions the way of the 8086, from the planned June release of version 3.0.

Tails' developers offer two reasons in their announcement: make the distro safer and save precious developer resources.

The group explains that at the start of 2016, its bug report system WhisperBack gathered data that a mere four per cent of Tails users were on 32-bit systems.

That, the group says, meant that fixing compatibility bugs isn't worth the effort.

“Tails has been using a 64-bit Linux kernel for a while on machines that support it,” the post says. “But all other programs included in Tails so far were built for 32-bit processors, and compatibility issues kept arising.”

They add that 64-bit systems have better ASLR (address space layout randomisation) and compulsory NX bit support.

ASLR makes it harder for an attacker to predict how a program is going to arrange data in memory. A wrong guess and the victim machine might simply crash and end the attack, and the much larger address space in 64-bit systems means it's much harder to seek out data by guessing.

The NX bit (in Intel systems implemented as XD, eXecute Disable; in AMD, Enhanced Virus Support) marks parts of memory as non-executable, and helps protect systems against malware exploiting buffer overruns.

Tails 3.0 is currently in beta. Its most recent release included security fixes like rejecting packets on the LAN sent to NetBIOS; and making the Seahorse key management utility use the Tor OnionBalance hidden service pool. Doing so “provides transport encryption and authentication of the keyserver”.

At the end of January, the current stable version of Tails was upgraded from 2.9.1 to 2.10. As the announcement warns, it's a major fix for a bunch of security bugs in the Tor Browser; BIND 9; the Icedove e-mail client; the PCSC-lite smart card access middleware; the libgd2 and libxml2 libraries; SAMBA; and a buffer overrun in the Tor comms client.

</blockquote>



#### 32bit linux distros

https://itsfoss.com/32-bit-linux-distributions/

- debian
  - slax
  - antix

Q4OS
Debian-based
Minimum Requirements for Q4OS:
RAM: 256 MB (Trinity Desktop) / 1 GB (Plasma Desktop)
CPU: 300 MHz (Trinity Desktop) / 1 GHz (Plasma Desktop)
Storage Space: 5 GB (Plasma Desktop) / 3 GB (Trinity Desktop)

MX Linux
based on Debian
Minimum System Requirements:
1 GB RAM (2 GB recommended for comfortable usage)
15 GB of disk space (20 GB recommended).

Linux Mint Debian Edition
Linux Mint based on Debian
Minimum System Requirements:
1 GB RAM (2 GB recommended for comfortable usage)
15 GB of disk space (20 GB recommended)

- openSUSE, rolling release edition (Tumbleweed)
  - not meant to run on vintage hardware — so you have to make sure that you have at least 2 GB RAM, 40+ GB storage space, and a dual-core processor.
- Emmabuntüs
  - aims to extend the life of the hardware to reduce the waste of raw materials with 32-bit support
- NixOS
  - NixOS is yet another independent Linux distribution that supports 32-bit systems.
  - It focuses on providing a reliable system where packages are isolated from each other.
  - Minimum System Requirements:
    - RAM: 768 MB
    - 8 GB Disk Space
    - Pentium 4 or equivalent
- Gentoo Linux
  - Minimum System Requirements:
    - 256 MB RAM
    - Pentium 4 or AMD equivalent
    - 2.5 GB Disk Space

Devuan
systemd-free
Minimum System Requirements:
RAM: 1 GB
CPU: Pentium 1.0 GHz

Void Linux
Minimum System Requirements:
96 MB RAM
Pentium 4 or AMD equivalent processor
Void is not available for the older 32-bit architectures like i386, i486, or i586
runit as the init system instead of systemd

Sparky Linux
one of the best lightweight Linux distributions tailored for beginners
Minimum System Requirements:
RAM: 128MB (CLI Edition), 256MB (LXDE, LXQt, Openbox) or 512MB (XFCE)
CPU: Pentium 4, or AMD Athlon
Disk space: 2 GB (CLI Edition), 10 GB (Home Edition), 20 GB (GameOver Edition)

Mageia
fork of Mandriva Linux
free operating system that is also potentially secure
Minimum System Requirements:
512 MB RAM (2 GB Recommended)
5 GB storage space for minimal installation (20 GB for regular installation)
CPU: Pentium 4, or AMD Athlon

Alpine Linux
Minimum System Requirements
RAM: 128MB (To start), 256MB (to install), 1GB (for GUI)
At least 700 MB space on a writable storage device.
full-fledged Linux Environment together with a huge collection of packages in repository
Alpine Linux is extremely popular among Docker users because it provides a minimal container image of just 5 MB in size

Funtoo is a Gentoo-based community-developed Linux distribution

Puppy Linux is a tiny Linux distro with almost no bundled software applications but basic tools.
Puppy Linux could be an option if nothing else works and you want the lightest distro.



## related

- [Combining NixOS with Qubes/Tails](https://www.reddit.com/r/NixOS/comments/y5qpta/combining_nixos_with_qubestails/)
  - [Spectrum OS](https://spectrum-os.org/) - process isolation
  - [jollheef/appvm](https://github.com/jollheef/appvm) - process isolation
- [Create squashfs iso with some persistence?](https://discourse.nixos.org/t/create-squashfs-iso-with-some-persistence/5787)



## mirrors

- https://github.com/milahu/nixos-tails
- http://it7otdanqu7ktntxzm427cba6i53w6wlanlh23v5i3siqmos47pzhvyd.onion/milahu/nixos-tails
- http://gg6zxtreajiijztyy5g6bt5o6l3qu32nrg7eulyemlhxwwl6enk6ghad.onion/milahu/nixos-tails
