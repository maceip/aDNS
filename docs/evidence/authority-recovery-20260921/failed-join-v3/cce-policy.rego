package policy

import future.keywords.every
import future.keywords.in

api_version := "0.11.0"
framework_version := "0.2.3"

fragments := [
  {
    "feed": "mcr.microsoft.com/aci/aci-cc-infra-fragment",
    "includes": [
      "containers",
      "fragments"
    ],
    "issuer": "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.3",
    "minimum_svn": "4"
  }
]

containers := [{"allow_elevated":false,"allow_stdio_access":true,"capabilities":{"ambient":[],"bounding":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"],"effective":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"],"inheritable":[],"permitted":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"]},"command":["python3","/opt/agentdns/run.py","--config","/config/node.json","--config-manifest","/config/manifest.json","--config-manifest-sha256","13d4c47222b339a1465e48ac7d7709b95055d9efad19cce2f3883119d707b662","--provision-tsig-file","/secrets/transfer-key.json"],"env_rules":[{"pattern":"OTEL_SDK_DISABLED=true","required":true,"strategy":"string"},{"pattern":"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","required":false,"strategy":"string"},{"pattern":"PYTHONPATH=/opt/agentdns/python","required":false,"strategy":"string"},{"pattern":"TERM=xterm","required":false,"strategy":"string"},{"pattern":"(?i)(FABRIC)_.+=.+","required":false,"strategy":"re2"},{"pattern":"HOSTNAME=.+","required":false,"strategy":"re2"},{"pattern":"T(E)?MP=.+","required":false,"strategy":"re2"},{"pattern":"FabricPackageFileName=.+","required":false,"strategy":"re2"},{"pattern":"HostedServiceName=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_API_VERSION=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_HEADER=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_SERVER_THUMBPRINT=.+","required":false,"strategy":"re2"},{"pattern":"azurecontainerinstance_restarted_by=.+","required":false,"strategy":"re2"},{"pattern":"^UVM_SECURITY_CONTEXT_DIR=/security-context[-a-zA-Z0-9]*$","required":false,"strategy":"re2"},{"pattern":"^APP_IDENTITY_ENDPOINT=.{1,2048}$","required":false,"strategy":"re2"}],"exec_processes":[],"id":"agentdnsport20260913.azurecr.io/primary:20260921-transfer-39d854d","layers":["6c553f19cf80dd98a5d90486c57e8eaa093f3e085b12a892da9561e91f5cf6b3","6b0b5c4b7a0ab95c74bcc8211dd5b81cde97ba131f79b4f667854a36d3cc9cef","c0a612ef76f7180291e3868972487e248f778d637790f813eed51c5789375304","f6656d0e6c25a00c3cd41a7b4220ac3bdd6a7d7361f63a0d596869ed3605d4f5","0833b4387c2d162c06dd74523cc485c44f2818e5df704d3d20c48d4df0178e99","78e1194b01703013d3277933d4d8898396e72f3499494413fb961f32b9c44e76","324cf2bd9b100b537212b096eb69d7d1c061b2b62e7cc6f1d46a9fe56f8b20e5","009b0329e3b253d7fc4c3895bcac0f4383b6e94a6c5e9c86619903919371f1b5"],"mounts":[{"destination":"/config","options":["rbind","rshared","ro"],"source":"sandbox:///tmp/atlas/secretsVolume/.+","type":"bind"},{"destination":"/secrets","options":["rbind","rshared","ro"],"source":"sandbox:///tmp/atlas/secretsVolume/.+","type":"bind"},{"destination":"/state","options":["rbind","rshared","rw"],"source":"sandbox:///tmp/atlas/emptydir/.+","type":"bind"},{"destination":"/durable","options":["rbind","rshared","rw"],"source":"sandbox:///tmp/atlas/azureFileVolume/.+","type":"bind"},{"destination":"/bootstrap-snapshots","options":["rbind","rshared","ro"],"source":"sandbox:///tmp/atlas/azureFileVolume/.+","type":"bind"},{"destination":"/etc/resolv.conf","options":["rbind","rshared","rw"],"source":"sandbox:///tmp/atlas/resolvconf/.+","type":"bind"}],"name":"primary","no_new_privileges":false,"seccomp_profile_sha256":"","signals":[],"user":{"group_idnames":[{"pattern":"","strategy":"any"}],"umask":"0022","user_idname":{"pattern":"","strategy":"any"}},"working_dir":"/state"},{"allow_elevated":false,"allow_stdio_access":true,"capabilities":{"ambient":[],"bounding":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"],"effective":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"],"inheritable":[],"permitted":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"]},"command":["python3","/app/secondary_aci.py"],"env_rules":[{"pattern":"^AGENTDNS_TRANSFER_KEY_B64=[A-Za-z0-9+/]{43}=$","required":true,"strategy":"re2"},{"pattern":"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","required":false,"strategy":"string"},{"pattern":"PYTHONDONTWRITEBYTECODE=1","required":false,"strategy":"string"},{"pattern":"PYTHONUNBUFFERED=1","required":false,"strategy":"string"},{"pattern":"TERM=xterm","required":false,"strategy":"string"},{"pattern":"(?i)(FABRIC)_.+=.+","required":false,"strategy":"re2"},{"pattern":"HOSTNAME=.+","required":false,"strategy":"re2"},{"pattern":"T(E)?MP=.+","required":false,"strategy":"re2"},{"pattern":"FabricPackageFileName=.+","required":false,"strategy":"re2"},{"pattern":"HostedServiceName=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_API_VERSION=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_HEADER=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_SERVER_THUMBPRINT=.+","required":false,"strategy":"re2"},{"pattern":"azurecontainerinstance_restarted_by=.+","required":false,"strategy":"re2"}],"exec_processes":[],"id":"agentdnsport20260913.azurecr.io/secondary:20260919-startup-pinned","layers":["ad7e8b43183eb7d3e25ebe7a49c2b5bdc10d8f0b070f0ca9d3ff1c07365d43e7","2994c1d662fc414d284aaa5c93da58133a704d691dd83d5e3e7d38a75ffc5823","e7909cbfde1bba404c2158e91ccae98a89cd47a59878b16ff4afdc5af3158ca3"],"mounts":[{"destination":"/etc/resolv.conf","options":["rbind","rshared","rw"],"source":"sandbox:///tmp/atlas/resolvconf/.+","type":"bind"}],"name":"secondary","no_new_privileges":false,"seccomp_profile_sha256":"","signals":[],"user":{"group_idnames":[{"pattern":"","strategy":"any"}],"umask":"0022","user_idname":{"pattern":"","strategy":"any"}},"working_dir":"/"},{"allow_elevated":false,"allow_stdio_access":true,"capabilities":{"ambient":[],"bounding":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"effective":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"inheritable":[],"permitted":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"]},"command":["/pause"],"env_rules":[{"pattern":"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","required":true,"strategy":"string"},{"pattern":"TERM=xterm","required":false,"strategy":"string"}],"exec_processes":[],"layers":["16b514057a06ad665f92c02863aca074fd5976c755d26bff16365299169e8415"],"mounts":[],"name":"pause-container","no_new_privileges":false,"seccomp_profile_sha256":"","signals":[],"user":{"group_idnames":[{"pattern":"","strategy":"any"}],"umask":"0022","user_idname":{"pattern":"","strategy":"any"}},"working_dir":"/"}]

allow_properties_access := true
allow_dump_stacks := false
allow_runtime_logging := false
allow_environment_variable_dropping := true
allow_unencrypted_scratch := false
allow_capability_dropping := true

mount_device := data.framework.mount_device
unmount_device := data.framework.unmount_device
mount_overlay := data.framework.mount_overlay
unmount_overlay := data.framework.unmount_overlay
create_container := data.framework.create_container
exec_in_container := data.framework.exec_in_container
exec_external := data.framework.exec_external
shutdown_container := data.framework.shutdown_container
signal_container_process := data.framework.signal_container_process
plan9_mount := data.framework.plan9_mount
plan9_unmount := data.framework.plan9_unmount
get_properties := data.framework.get_properties
dump_stacks := data.framework.dump_stacks
runtime_logging := data.framework.runtime_logging
load_fragment := data.framework.load_fragment
scratch_mount := data.framework.scratch_mount
scratch_unmount := data.framework.scratch_unmount
rw_mount_device := data.framework.rw_mount_device

reason := {"errors": data.framework.errors}