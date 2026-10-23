"""Read and use the phone interface."""
import asyncio
import re
import xml.etree.ElementTree as ET

class UI:
    def __init__(self,d):self.d=d
    async def nodes(self):
        p='/data/local/tmp/ypso-relay-restore-'+self.d.role+'.xml'
        for _ in range(3):
            try:
                await self.d.shell('uiautomator','dump',p,timeout=18)
                raw,status=await self.d.shell('cat',p,check=False)
                if status==0:return list(ET.fromstring(raw).iter('node'))
            except (TimeoutError,ET.ParseError):pass
            finally:await self.d.shell('rm','-f',p,check=False)
        raise RuntimeError('No fresh Settings UI hierarchy')
    async def tap(self,n,packages):
        if n.get('package') not in packages:raise RuntimeError('Unexpected UI package')
        a,b,c,d=map(int,re.findall(r'\d+',n.get('bounds','')))
        await self.d.shell('input','tap',(a+c)//2,(b+d)//2);await asyncio.sleep(.5)
    async def text(self,ns,text,packages):
        found=[n for n in ns if n.get('text')==text and n.get('package') in packages]
        if len(found)!=1:raise RuntimeError('Expected one named restoration control: '+text)
        await self.tap(found[0],packages)
    async def resource(self,ns,res,packages):
        found=[n for n in ns if n.get('resource-id')==res and n.get('package') in packages]
        if len(found)!=1:raise RuntimeError('Expected one restoration resource')
        await self.tap(found[0],packages)
    async def action(self,name,*extras):
        await self.d.shell('am','start','-W','-f','0x10008000','-a',name,*extras)
    async def launch(self,package):
        raw,_=await self.d.shell('cmd','package','resolve-activity','--brief','-a','android.intent.action.MAIN','-c','android.intent.category.LAUNCHER',package)
        component=raw.decode().strip().splitlines()[-1]
        if not component.startswith(package+'/'):raise RuntimeError('Unexpected launch component')
        await self.d.shell('am','start','-W','-n',component)
    def texts(self,ns):return [n.get('text','') for n in ns]


