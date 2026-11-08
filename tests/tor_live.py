#!/usr/bin/env python3
"""Opt-in live Tor test. Requires tor on PATH, gpg, and Python pexpect.
Uses only generated temporary identities; never accesses personal signing keys.
Run after cargo build: python3 tests/tor_live.py
"""
import os,pathlib,subprocess,tempfile,time
import pexpect
base=pathlib.Path(tempfile.mkdtemp(prefix='git-safe-live-'))
binary=os.environ.get('GIT_SAFE_BIN',str(pathlib.Path(__file__).resolve().parents[1]/'target/debug/git-safe'))
children=[]
def identity(name):
 home=base/name;home.mkdir(mode=0o700)
 env=os.environ.copy();env['GNUPGHOME']=str(home);env['XDG_DATA_HOME']=str(base/(name+'-data'))
 subprocess.run(['gpg','--batch','--pinentry-mode','loopback','--passphrase','','--quick-gen-key',name+' <'+name+'@example.invalid>','ed25519','sign','never'],env=env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 listing=subprocess.check_output(['gpg','--with-colons','--list-keys'],env=env,stderr=subprocess.DEVNULL).decode()
 fpr=next(l.split(':')[9] for l in listing.splitlines() if l.startswith('fpr:'))
 return env,fpr

def expect(child,pattern,seconds):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  i=child.expect([pattern,pexpect.EOF,pexpect.TIMEOUT],timeout=min(20,end-time.monotonic()))
  if i==0:return child.match
  if i==1:raise RuntimeError('CLI exited: '+child.before[-1000:])
  print('Still waiting for '+pattern[:30],flush=True)
 raise RuntimeError('Timed out: '+child.before[-1000:])
try:
 ae,af=identity('alice');be,bf=identity('bob')
 sender=pexpect.spawn(binary,['peer','invite','--key',af,'--peer-id','bob'],env=ae,encoding='utf8',timeout=200);children.append(sender)
 match=expect(sender,r'(git-safe://[a-z2-7]{56}\.onion/[0-9a-f]{64})',200)
 invite=match.group(1)
 print('Sender published an invitation',flush=True)
 receiver=pexpect.spawn(binary,['peer','connect','--id','alice','--key',bf],env=be,encoding='utf8',timeout=200);children.append(receiver)
 expect(receiver,'Paste the private invitation:',10);receiver.sendline(invite)
 expect(sender,r'\[y/N\]',260);sender.sendline('y')
 print('Sender approved reciprocal key',flush=True)
 expect(receiver,r'\[y/N\]',100);receiver.sendline('y')
 receiver.expect(pexpect.EOF,timeout=30);sender.expect(pexpect.EOF,timeout=30)
 receiver.close();sender.close()
 assert receiver.exitstatus==0 and sender.exitstatus==0,(receiver.exitstatus,sender.exitstatus,sender.before[-1200:],receiver.before[-1200:])
 for env,expected in [(ae,'bob'),(be,'alice')]:
  listing=subprocess.check_output([binary,'keys','list'],env=env).decode();assert listing.startswith(expected+'\t'),listing
 print('PASS: mutual public-key exchange over real Tor and both SQLite imports',flush=True)
 print('Temporary identities will be removed',flush=True)
finally:
 for c in children:
  if c.isalive():
   c.sendcontrol('c')
   try:c.expect(pexpect.EOF,timeout=5)
   except pexpect.ExceptionPexpect:c.terminate(force=True)

 for name in ['alice','bob']:
  subprocess.run(['gpgconf','--homedir',str(base/name),'--kill','gpg-agent'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 import shutil
 shutil.rmtree(base)
