Built-in BOF objects in this directory were built from TrustedSec CS-Situational-Awareness-BOF.

Source: https://github.com/trustedsec/CS-Situational-Awareness-BOF
Commit: ee9459cc4f42c6b025797bad22ffe8d9f1cf6487
License: GPL-2.0

Alias mapping:
- ldapsearch -> SA/ldapsearch
- adcs_enum -> SA/adcs_enum
- password-policy -> SA/get_password_policy
- local-sessions -> SA/enumLocalSessions
- net-shares -> SA/netshares
- regsession -> SA/regsession
- netloggedon -> SA/netloggedon2
- schtasks-enum -> SA/schtasksenum

TrustedSec rebuild command shape:
  x86_64-w64-mingw32-gcc -I src/common -Os -c src/SA/<name>/entry.c -DBOF -o <alias>.x64.o

Additional built-in BOF sources:

- xpipe.x64.o
  Source: https://github.com/boku7/xPipe
  Commit: 5177b24863439a6e87f01be51704749fbdcb77e4
  License: MIT
  Alias: xpipe -> xpipe.o

- msi-search.x64.o
  Source: https://github.com/mandiant/msi-search
  Commit: bbd5cc34d3df37c54ac5bcbb0602f87484b102ab
  License: Apache-2.0
  Alias: msi-search -> msi_search.x64.o

- safe-harbor.x64.o
  Source: https://github.com/ibaiC/SafeHarbor-BOF
  Commit: bcd18e3fe0c07c3e4ad49a971ac6554c1b123a42
  License: no repository license file
  Alias: safe-harbor -> x64/Release/bof.x64.o

- priv-*.x64.o
  Source: https://github.com/mertdas/PrivKit
  Commit: 276fc9074c6437f8610fc78b309b80c3b6eebab2
  License: GPL-3.0
  Aliases: priv-always-install-elevated, priv-autologon, priv-credential-manager,
           priv-hijackable-path, priv-modifiable-autorun, priv-modifiable-service,
           priv-powershell-history, priv-token-privileges, priv-uac-status,
           priv-unquoted-service-path

- sql-*.x64.o
  Source: https://github.com/Tw1sm/SQL-BOF
  Commit: e7fbf9ec36dd031a0ccc4b61eca00ff5baeee96e
  License: GPL-2.0
  Aliases: sql-1434udp, sql-info, sql-whoami, sql-impersonate, sql-links,
           sql-users, sql-databases, sql-tables, sql-columns, sql-rows,
           sql-search, sql-query, sql-agentstatus, sql-checkrpc
