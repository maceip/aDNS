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

containers := [{"allow_elevated":false,"allow_stdio_access":true,"capabilities":{"ambient":[],"bounding":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"],"effective":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"],"inheritable":[],"permitted":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"]},"command":["python3","/app/capture_aci.py"],"env_rules":[{"pattern":"AGENTDNS_CAPTURE_CONFIG_B64=eyJyZXF1ZXN0X2lkIjoiYWNpLWNhcHR1cmUtMjAyNjA5MTMtMDEiLCJhdWRpZW5jZSI6ImNjZjovL2FnZW50ZG5zLnRlc3QiLCJncmFudF9pZCI6ImFjaS10ZXN0LW93bmVyIiwiem9uZSI6ImV4YW1wbGUudGVzdC4iLCJyb2xlIjoibXgtZWRnZSIsIm1haWxib3hfZG9tYWluIjoiZXhhbXBsZS50ZXN0LiIsInNlcnZpY2VfaG9zdCI6Im1haWwuZXhhbXBsZS50ZXN0LiIsImFkZHJlc3NlcyI6eyJpcHY0IjpbIjE5Mi4wLjIuMSJdLCJpcHY2IjpbIjIwMDE6ZGI4OjoxIl19LCJwb3J0cyI6WzI1LDQ2NSw5OTNdLCJsZWFzZV9zZWNvbmRzIjozNjAwLCJsaXN0ZW5fYWRkcmVzcyI6IjAuMC4wLjAiLCJsaXN0ZW5fcG9ydCI6ODA4MH0=","required":true,"strategy":"string"},{"pattern":"^AGENTDNS_CAPTURE_TOKEN=[0-9a-f]{64}$","required":true,"strategy":"re2"},{"pattern":"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","required":false,"strategy":"string"},{"pattern":"PYTHONDONTWRITEBYTECODE=1","required":false,"strategy":"string"},{"pattern":"PYTHONUNBUFFERED=1","required":false,"strategy":"string"},{"pattern":"TERM=xterm","required":false,"strategy":"string"},{"pattern":"(?i)(FABRIC)_.+=.+","required":false,"strategy":"re2"},{"pattern":"HOSTNAME=.+","required":false,"strategy":"re2"},{"pattern":"T(E)?MP=.+","required":false,"strategy":"re2"},{"pattern":"FabricPackageFileName=.+","required":false,"strategy":"re2"},{"pattern":"HostedServiceName=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_API_VERSION=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_HEADER=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_SERVER_THUMBPRINT=.+","required":false,"strategy":"re2"},{"pattern":"azurecontainerinstance_restarted_by=.+","required":false,"strategy":"re2"},{"pattern":"^UVM_SECURITY_CONTEXT_DIR=/security-context[-a-zA-Z0-9]*$","required":false,"strategy":"re2"}],"exec_processes":[],"layers":["ad7e8b43183eb7d3e25ebe7a49c2b5bdc10d8f0b070f0ca9d3ff1c07365d43e7","cc8be6a8e40d6bc3f2e5d53637c13591634815c8e709ac20fa95825abca1c101","5367cbe2e8bdc57e4ca49b8881a44703215f2d8e8253b541c4c26f5fe4896a10","217be9d86304b4da712e0e166065e48f0054609994a7666aa26198164fe9c2cf"],"mounts":[{"destination":"/etc/resolv.conf","options":["rbind","rshared","rw"],"source":"sandbox:///tmp/atlas/resolvconf/.+","type":"bind"}],"name":"capture","no_new_privileges":false,"seccomp_profile_sha256":"","signals":[],"user":{"group_idnames":[{"pattern":"","strategy":"any"}],"umask":"0022","user_idname":{"pattern":"","strategy":"any"}},"working_dir":"/"},{"allow_elevated":false,"allow_stdio_access":true,"capabilities":{"ambient":[],"bounding":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"effective":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"inheritable":[],"permitted":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"]},"command":["/pause"],"env_rules":[{"pattern":"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","required":true,"strategy":"string"},{"pattern":"TERM=xterm","required":false,"strategy":"string"}],"exec_processes":[],"layers":["16b514057a06ad665f92c02863aca074fd5976c755d26bff16365299169e8415"],"mounts":[],"name":"pause-container","no_new_privileges":false,"seccomp_profile_sha256":"","signals":[],"user":{"group_idnames":[{"pattern":"","strategy":"any"}],"umask":"0022","user_idname":{"pattern":"","strategy":"any"}},"working_dir":"/"}]

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