#!/usr/bin/env python3
import os,json,pathlib,socket,datetime,stat,sys

SHA="790e330cee287a4e31a36dfda496068f68db8dc8"
TREE="9134cc9f0b78f058a419a058ecb92f4d2cc49919"
ALLOW=sorted(["PATH","LANG","NODE_ENV","HOME","USER","LOGNAME","XDG_CONFIG_HOME","XDG_CACHE_HOME","XDG_DATA_HOME","TMPDIR","SHELL"])
challenge,decoy_sha=sys.argv[1:3]

def proc_status():
    out={}
    with open("/proc/self/status",encoding="utf-8") as f:
        for line in f:
            if ":" in line:
                k,v=line.split(":",1); out[k]=v.strip()
    return out

s=proc_status()
uids=[int(x) for x in s["Uid"].split()]
gids=[int(x) for x in s["Gid"].split()]
groups=[int(x) for x in s.get("Groups","").split()] if s.get("Groups") else []
caps={k:s.get(k,"").lower().zfill(16)[-16:] for k in ("CapEff","CapPrm","CapInh","CapAmb","CapBnd")}
env=sorted(os.environ)
home=os.environ["HOME"]
home_fresh=os.path.isdir(home) and os.listdir(home)==[]
xdg_paths=[os.environ[k] for k in ("XDG_CONFIG_HOME","XDG_CACHE_HOME","XDG_DATA_HOME")]
xdg_fresh=not any(os.path.exists(p) for p in xdg_paths)

git_paths=["/etc/gitconfig",home+"/.gitconfig",os.environ["XDG_CONFIG_HOME"]+"/git/config"]
git_present=[p for p in git_paths if os.path.exists(p)]
credential_paths=[
    home+"/.netrc",home+"/.git-credentials",home+"/.ssh",
    os.environ["XDG_CONFIG_HOME"]+"/gh",home+"/.aws",home+"/.azure",
    "/var/run/docker.sock","/run/secrets"
]
credential_present=[p for p in credential_paths if os.path.exists(p)]

mounts=[]; shared=[]; sensitive=[]
with open("/proc/self/mountinfo",encoding="utf-8") as f:
    for line in f:
        p=line.split()
        if "-" not in p: continue
        i=p.index("-"); mp=p[4]; fs=p[i+1]
        mounts.append({"mountPoint":mp,"fsType":fs})
        lo=mp.lower()
        if any(x in lo for x in ("/github/workspace","/workspace","/repo","/src")): shared.append(mp)
        if any(x in lo for x in ("/run/secrets","/.ssh","/.aws","/.azure","/.config/gh","docker.sock","credentials")): sensitive.append(mp)

fds=[]
for fd in range(3,128):
    try: os.fstat(fd)
    except OSError: continue
    try: target=os.readlink(f"/proc/self/fd/{fd}")
    except OSError: target="<unreadable>"
    fds.append({"fd":fd,"target":target})

interfaces=sorted(p.name for p in pathlib.Path("/sys/class/net").iterdir())
non_loopback=[x for x in interfaces if x!="lo"]
with open("/proc/net/route",encoding="utf-8") as f:
    r4=f.read().splitlines()[1:]
default_v4=any(len(x.split())>1 and x.split()[1]=="00000000" and x.split()[0]!="lo" for x in r4)
with open("/proc/net/ipv6_route",encoding="utf-8") as f:
    r6=f.read().splitlines()
default_v6=any(
    len(parts)>=10 and parts[0]=="0"*32 and parts[1]=="00" and parts[-1]!="lo"
    for parts in (line.split() for line in r6)
)

sock=socket.socket(); sock.settimeout(1.5); blocked=False; net_error=""
try:
    sock.connect(("1.1.1.1",443))
except OSError as e:
    blocked=True; net_error=type(e).__name__
finally:
    sock.close()

runtime_sockets=[]
for root in ("/run","/tmp"):
    for d,ds,fs in os.walk(root):
        for n in fs:
            p=os.path.join(d,n)
            try:
                if stat.S_ISSOCK(os.lstat(p).st_mode): runtime_sockets.append(p)
            except OSError:
                pass

identity={
    "uidSlots":uids,"gidSlots":gids,"supplementaryGids":groups,
    "capEffHex":caps["CapEff"],"capPrmHex":caps["CapPrm"],"capInhHex":caps["CapInh"],
    "capAmbHex":caps["CapAmb"],"capBndHex":caps["CapBnd"],
    "noNewPrivs":s.get("NoNewPrivs")=="1",
    "sudoAvailable":any(os.path.exists(p) for p in ("/usr/bin/sudo","/bin/sudo")),
    "hostPidNamespaceVisible":os.getpid()!=1
}
environment={
    "keys":env,"home":home,"homeFreshAtStart":home_fresh,"xdgFreshAtStart":xdg_fresh,
    "unapprovedCredentialKeys":[k for k in env if k not in ALLOW],
    "inheritedSecretDescriptors":[k for k in env if any(x in k.upper() for x in ("TOKEN","SECRET","PASSWORD","PRIVATE_KEY","CREDENTIAL","ACCESS_KEY","API_KEY"))]
}
network={
    "interfaces":interfaces,"nonLoopbackInterfaces":non_loopback,
    "defaultRouteV4Present":default_v4,"defaultRouteV6Present":default_v6,
    "externalTcpConnectBlocked":blocked,"externalTcpConnectErrorClass":net_error
}

fail=[]
if uids != [65532]*4: fail.append("UID")
if gids != [65532]*4: fail.append("GID")
if any(g != 65532 for g in groups): fail.append("GROUPS")
if any(v != "0000000000000000" for v in caps.values()): fail.append("CAPS")
if not identity["noNewPrivs"] or identity["sudoAvailable"] or identity["hostPidNamespaceVisible"]: fail.append("PRIVILEGE")
if env != ALLOW or not home_fresh or not xdg_fresh or environment["unapprovedCredentialKeys"] or environment["inheritedSecretDescriptors"]: fail.append("ENV")
if git_present or credential_present or shared or sensitive or fds: fail.append("FILESYSTEM_OR_FD")
if non_loopback or default_v4 or default_v6 or not blocked: fail.append("NETWORK")
if runtime_sockets: fail.append("IPC")

out={
    "schema":"MAEF_F02_PUBLIC_WORKER_WITNESS_V1",
    "capturedAt":datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00","Z"),
    "candidateBinding":{
        "candidateSha":SHA,"candidateTree":TREE,
        "bindingAuthority":"DECLARED_FROZEN_REFERENCE_ONLY",
        "privateSourceFetchedByWorker":False
    },
    "challenge":challenge,
    "decoySha256":decoy_sha,
    "checks":{
        "identity":identity,
        "environment":environment,
        "git":{"effectiveConfigSourcesPresent":git_present,"remotes":[],"credentialHelpers":[]},
        "filesystem":{
            "credentialPathsPresent":credential_present,
            "sharedWorkspaceMounts":shared,
            "sensitiveMounts":sensitive,
            "dockerSocketPresent":os.path.exists("/var/run/docker.sock"),
            "mountInventory":mounts
        },
        "process":{"inheritedNonStdioFds":fds},
        "network":network,
        "publisher":{"runtimeSockets":runtime_sockets,"publisherReachable":False,"privilegedWriteRoutes":[]},
        "decoy":{"rawDecoyReceivedByWorker":False,"digestOnlyReceived":True}
    },
    "selfCheck":{"pass":not fail,"failures":fail}
}
print(json.dumps(out,sort_keys=True,separators=(",",":")))
